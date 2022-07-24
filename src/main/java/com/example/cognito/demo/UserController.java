package com.example.cognito.demo;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentityClient;
import com.amazonaws.services.cognitoidentity.model.Credentials;
import com.amazonaws.services.cognitoidentity.model.GetIdResult;
import com.amazonaws.services.cognitoidentity.model.InvalidParameterException;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AWSCognitoIdentityProviderException;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserRequest;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserResult;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeRequest;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeResult;
import com.amazonaws.services.cognitoidp.model.AdminSetUserPasswordRequest;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;
import com.amazonaws.services.cognitoidp.model.ChallengeNameType;
import com.amazonaws.services.cognitoidp.model.DeliveryMediumType;
import com.amazonaws.services.cognitoidp.model.MessageActionType;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.S3Object;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentity.CognitoIdentityClient;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetCredentialsForIdentityResponse;
import software.amazon.awssdk.services.cognitoidentity.model.GetIdRequest;
import software.amazon.awssdk.services.cognitoidentity.model.GetIdResponse;

@RestController
@RequestMapping(path = "/api/users")
public class UserController {

    @Autowired
    private AWSCognitoIdentityProvider cognitoClient;
    
    CognitoIdentityClient cognitoIdentityClient = CognitoIdentityClient.builder()
            .region(Region.AP_SOUTH_1)
            .build();
    

    @Value(value = "${aws.cognito.userPoolId}")
    private String userPoolId;
    @Value(value = "${aws.cognito.clientId}")
    private String clientId;

    @PostMapping(path = "/sign-up")
    public void signUp(@RequestBody  UserSignUpRequest userSignUpRequest) {

        try {

            AttributeType emailAttr =
                    new AttributeType().withName("email").withValue(userSignUpRequest.getEmail());
            AttributeType emailVerifiedAttr =
                    new AttributeType().withName("email_verified").withValue("true");

            AdminCreateUserRequest userRequest = new AdminCreateUserRequest()
                    .withUserPoolId(userPoolId).withUsername(userSignUpRequest.getUsername())
                    .withTemporaryPassword(userSignUpRequest.getPassword())
                    .withUserAttributes(emailAttr, emailVerifiedAttr)
                    .withMessageAction(MessageActionType.SUPPRESS)
                    .withDesiredDeliveryMediums(DeliveryMediumType.EMAIL);

            AdminCreateUserResult createUserResult = cognitoClient.adminCreateUser(userRequest);

            System.out.println("User " + createUserResult.getUser().getUsername()
                    + " is created. Status: " + createUserResult.getUser().getUserStatus());

            // Disable force change password during first login
            AdminSetUserPasswordRequest adminSetUserPasswordRequest =
                    new AdminSetUserPasswordRequest().withUsername(userSignUpRequest.getUsername())
                            .withUserPoolId(userPoolId)
                            .withPassword(userSignUpRequest.getPassword()).withPermanent(true);

            cognitoClient.adminSetUserPassword(adminSetUserPasswordRequest);

        } catch (AWSCognitoIdentityProviderException e) {
            System.out.println(e.getErrorMessage());
        } catch (Exception e) {
            System.out.println("Setting user password");
        }
    }



    @PostMapping(path = "/sign-in")
    public @ResponseBody  UserSignInResponse signIn(
            @RequestBody  UserSignInRequest userSignInRequest) {
    	
        UserSignInResponse userSignInResponse = new UserSignInResponse();

        final Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", userSignInRequest.getUsername());
        authParams.put("PASSWORD", userSignInRequest.getPassword());

        final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
        authRequest.withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH).withClientId(clientId)
                .withUserPoolId(userPoolId).withAuthParameters(authParams);

        try {
            AdminInitiateAuthResult result = cognitoClient.adminInitiateAuth(authRequest);

            AuthenticationResultType authenticationResult = null;

            if (result.getChallengeName() != null && !result.getChallengeName().isEmpty()) {

                System.out.println("Challenge Name is " + result.getChallengeName());

                if (result.getChallengeName().contentEquals("NEW_PASSWORD_REQUIRED")) {
                    if (userSignInRequest.getPassword() == null) {
                        throw new CustomException(
                                "User must change password " + result.getChallengeName());

                    } else {

                        final Map<String, String> challengeResponses = new HashMap<>();
                        challengeResponses.put("USERNAME", userSignInRequest.getUsername());
                        challengeResponses.put("PASSWORD", userSignInRequest.getPassword());
                        // add new password
                        challengeResponses.put("NEW_PASSWORD", userSignInRequest.getNewPassword());

                        final AdminRespondToAuthChallengeRequest request =
                                new AdminRespondToAuthChallengeRequest()
                                        .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                                        .withChallengeResponses(challengeResponses)
                                        .withClientId(clientId).withUserPoolId(userPoolId)
                                        .withSession(result.getSession());

                        AdminRespondToAuthChallengeResult resultChallenge =
                                cognitoClient.adminRespondToAuthChallenge(request);
                        authenticationResult = resultChallenge.getAuthenticationResult();

                        
                        userSignInResponse.setAccessToken(authenticationResult.getAccessToken());
                        userSignInResponse.setIdToken(authenticationResult.getIdToken());
                        userSignInResponse.setRefreshToken(authenticationResult.getRefreshToken());
                        userSignInResponse.setExpiresIn(authenticationResult.getExpiresIn());
                        userSignInResponse.setTokenType(authenticationResult.getTokenType());
                    }

                } else {
                    throw new CustomException(
                            "User has other challenge " + result.getChallengeName());
                }
            } else {

                System.out.println("User has no challenge");
            
                authenticationResult = result.getAuthenticationResult();

                userSignInResponse.setAccessToken(authenticationResult.getAccessToken());
                userSignInResponse.setIdToken(authenticationResult.getIdToken());
                userSignInResponse.setRefreshToken(authenticationResult.getRefreshToken());
                userSignInResponse.setExpiresIn(authenticationResult.getExpiresIn());
                userSignInResponse.setTokenType(authenticationResult.getTokenType());
            }
            
            

        } catch (InvalidParameterException e) {
            throw new CustomException(e.getErrorMessage());
        } catch (Exception e) {
            throw new CustomException(e.getMessage());
        }
        cognitoClient.shutdown();
        return userSignInResponse;

    }

    @GetMapping(path = "/detail")
    public @ResponseBody  UserDetail getUserDetail() {

        UserDetail userDetail = new UserDetail();
        userDetail.setFirstName("Test");
        userDetail.setLastName("demo");
        userDetail.setEmail("testdemo@xyz.com");
        return userDetail;
    }
    
    @PostMapping(path = "/temp")
    public void tempCredentials()
    { 	
    	String identityPoolId = "aws_cognito_identity_pool_id";
    	String identityId = getClientID(cognitoIdentityClient, identityPoolId);
    	getCredentialsForIdentity(cognitoIdentityClient, identityId);
    	cognitoIdentityClient.close();	
    }
    
    @PostMapping(path = "/verify")
    public void s3test()
    {
        String accessKeyId = "temporary_access_key_d";

        String secretAccessKey="temporary_secret_access_key";

        String sessionToken = "session_token";

        BasicSessionCredentials basicSessionCredentials = new BasicSessionCredentials(accessKeyId,secretAccessKey, sessionToken);
    	
    	AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion("aws-region")
                .withCredentials(new AWSStaticCredentialsProvider(basicSessionCredentials))
                .build();
    	S3Object a = s3.getObject("aws-s3- bucket-name","file name");
    	if(a!=null)System.out.println("-----------------");
    	
    }

    public  String getClientID(CognitoIdentityClient cognitoClient, String identityPoolId){
        try {
            String openIdToken = "open_id_token";

            Map<String,String> logins = new HashMap<>();
            logins.put("identity_pool_id", openIdToken);

            GetIdRequest request = GetIdRequest.builder()
                    .identityPoolId(identityPoolId)
                    .build();

            GetIdResponse response = cognitoClient.getId(request);
     
            System.out.println("Identity ID " + response.identityId());
            return response.identityId();

        } catch (Exception e){
            e.printStackTrace();
        }
        return "id not found";
    }

    public static <CognitoIdentityCredentials> void getCredentialsForIdentity(CognitoIdentityClient cognitoClient, String identityId) {

        try {

            String openIdToken = "open_id_token";
            Map<String,String> logins = new HashMap<>();
            logins.put("identity_pool_id", openIdToken);
        
            GetCredentialsForIdentityRequest getCredentialsForIdentityRequest = GetCredentialsForIdentityRequest.builder()
                    .identityId(identityId)
                    .build();
            
            GetCredentialsForIdentityResponse response = cognitoClient.getCredentialsForIdentity(getCredentialsForIdentityRequest);
            System.out.println("Identity ID: " + response.identityId() + "\nAccess key ID: " + response.credentials().accessKeyId());
            System.out.println("Secret key: "+response.credentials().secretKey());
            System.out.println("Session Token: "+response.credentials().sessionToken());   
         
            System.out.println("Exp time "+ response.credentials().expiration());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
   
}

    