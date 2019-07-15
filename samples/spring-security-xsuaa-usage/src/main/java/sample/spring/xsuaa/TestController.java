package sample.spring.xsuaa;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.Token;
import com.sap.cloud.security.xsuaa.token.XsuaaToken;
import com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlows;

@RestController
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    /**
     * The injected factory for XSUAA token flows.
     */
    @Autowired
    private XsuaaTokenFlows xsuaaTokenFlows;
    
    /**
     * The XSUAA binding information from the environment.
     */
    @Autowired
    private XsuaaServiceConfiguration xsuaaBindindInformation;
    
    /**
     * A (fake) data layer showing global method security features of Spring Security
     * in combination with tokens from XSUAA.
     */
    @Autowired
    private DataService dataService;

    /**
     * Returns the detailed information of the XSUAA JWT token.
     * Uses a Token retrieved from the security context of Spring Security.
     *
     * @param token the XSUAA token from the request injected by Spring Security.
     * @return the requested address.
     * @throws Exception in case of an internal error.
     */
    @GetMapping(value = "/v1/sayHello")
    public Map<String, String> sayHello(@AuthenticationPrincipal Token token) {

        logger.info("Got the Xsuaa token: " + token);
        logger.info(token.toString());

        Map<String, String> result = new HashMap<>();
        result.put("grant type", token.getGrantType());
        result.put("client id", token.getClientId());
        result.put("subaccount id", token.getSubaccountId());
        result.put("logon name", token.getLogonName());
        result.put("family name", token.getFamilyName());
        result.put("given name", token.getGivenName());
        result.put("email", token.getEmail());
        result.put("authorities", String.valueOf(token.getAuthorities()));
        result.put("scopes", String.valueOf(token.getScopes()));

        return result;
    }

    /**
     * Returns some generic information from the JWT token.<br>
     * Uses a Jwt retrieved from the security context of Spring Security.
     *
     * @param jwt the JWT from the request injected by Spring Security.
     * @return the requested address.
     * @throws Exception in case of an internal error.
     */
    @GetMapping(value = "/v2/sayHello")
    public String sayHello(@AuthenticationPrincipal Jwt jwt) {

        logger.info("Got the JWT: " + jwt);

        logger.info(jwt.toString());

        return "Hello Jwt-Protected World!";
    }
    
    /**
     * Returns some generic information from the XsuaaToken.<br>
     * Uses a XsuaaToken retrieved from the security context of Spring Security.
     * <p>
     * <b>Note:</b> XsuaaToken is just a Jwt, it is derived from it, and adds a few more convenience methods.
     *
     * @param jwt the JWT from the request injected by Spring Security.
     * @return the requested address.
     * @throws Exception in case of an internal error.
     */
    @GetMapping(value = "/v3/sayHello")
    public String sayHello(@AuthenticationPrincipal XsuaaToken xsuaaToken) {

        logger.info("Got the JWT (with XSUAA convenience on top): " + xsuaaToken);

        logger.info(xsuaaToken.toString());

        return "Hello Jwt-Protected XSUAA World! Notice: an XsuaaToken is still a Jwt!";
    }

    /**
     * An endpoint showing how to use Spring method security.
     * Only if the request principal has the given scope will the
     * method be called. Otherwise a 403 error will be returned.
     */
    @GetMapping(value = "/v1/method")
    @PreAuthorize("hasAuthority('Read')")
    public String callMethodRemotely() {
        return "Read-protected method called!";
    }

    /**
     * More advanced showcase for global method security.
     * The {@link DataService} interface uses annotated methods
     * and when the {@link DataService} gets injected as a bean
     * Spring Security wraps it with a security-enforcing wrapper.
     * The result is, that the {@link DataService#readSensitiveData()} method
     * will only be called if the proper scopes are available.
     *
     * @return the sensitive data read from the {@link DataService} or fails
     * with an access denied error.
     *
     * @see {@link DataService}.
     */
    @GetMapping(value = "/v1/readData")
    public String readFromDataService() {
        return dataService.readSensitiveData();
    }
    
    /**
     * REST endpoint showing how to fetch a Client Credentials Token from XSUAA using the 
     * {@link XsuaaTokenFlows} bean injected by Spring and exposed by the XSUAA client library 
     * implementation. 
     * @param jwt - the Jwt as a result of authentication.
     * @return the Client Credentials Token fetched from XSUAA. Don't do this in production!
     * @throws Exception in case of any errors.
     */
    @RequestMapping(value = "/v1/clientCredentialsToken", method = RequestMethod.GET)
    public Jwt fetchClientCredentialsToken(@AuthenticationPrincipal Jwt jwt) throws Exception { 
        
        String baseUrl = xsuaaBindindInformation.getUaaUrl();
        String clientId = xsuaaBindindInformation.getClientId();
        String clientSecret = xsuaaBindindInformation.getClientSecret();
        
        Jwt ccfToken = xsuaaTokenFlows.clientCredentialsTokenFlow(URI.create(baseUrl))
                .client(clientId)
                .secret(clientSecret)
                .execute();
 
        logger.info("Got the Client Credentials Flow Token: {}", ccfToken.getTokenValue());
        
        return ccfToken;
    }
    
    /**
     * REST endpoint showing how to retrieve a refreshed token from XSUAA using the 
     * {@link XsuaaTokenFlows} bean injected by Spring and exposed by the XSUAA client library 
     * implementation. 
     * @param jwt - the Jwt as a result of authentication.
     * @return the Client Credentials Token fetched from XSUAA. Don't do this in production!
     * @throws Exception in case of any errors.
     */
    @RequestMapping(value = "/v1/refreshToken", method = RequestMethod.GET)
    public Jwt refreshToken(@AuthenticationPrincipal Jwt jwt) throws Exception { 
        
        String baseUrl = xsuaaBindindInformation.getUaaUrl();
        String clientId = xsuaaBindindInformation.getClientId();
        String clientSecret = xsuaaBindindInformation.getClientSecret();
        
        Jwt refreshToken = xsuaaTokenFlows.refreshTokenFlow(URI.create(baseUrl))
        		.refreshToken("Your refresh token goes here. You get this from the OAuth server.")
                .client(clientId)
                .secret(clientSecret)
                .execute();
 
        logger.info("Got the refreshed token: {}", refreshToken.getTokenValue());
        logger.info("You could now inject this into Spring's SecurityContext, using: SecurityContextHolder.getContext().setAuthentication(...).");
                
        return refreshToken;
    }
    
    /**
     * REST endpoint showing how to exchange a token from XSUAA for another one intended for another service.
     * This endpoint shows how to use the {@link XsuaaTokenFlows} bean injected by Spring and exposed by the XSUAA client 
     * library implementation.
     * <p>
     * The idea behind a user token exchange is to separate service-specific access scopes into separate tokens.
     * For example, if Service A has scopes specific to its functionality and Service B has other scopes, the intention is
     * that there is no single Jwt token that contains all of these scopes.<br>
     * Rather the intention is to have a Jwt token to call Service A (containing just the scopes of Service A), 
     * and another one to call Service B (containing just the scopes of Service B). An application calling Service A and 
     * B on behalf of a user therefore has to exchange the user's Jwt token against a token for Service A and B respectively
     * before calling these services. This scenario is handled by the user token flow.
     * <p>
     * <b>Note:</b> In order to be able to exchange the token, the input token needs to contain the scope {@code uaa.user}.<br>
     * Note also, that the client ID and client secret are the credentials injected by the service you are exchanging the token for.  
     *
     * 
     * @param jwt - the Jwt as a result of authentication.
     * @return the Client Credentials Token fetched from XSUAA. Don't do this in production!
     * @throws Exception in case of any errors.
     */
    @RequestMapping(value = "/v1/userTokenFlow", method = RequestMethod.GET)
    public Jwt userTokenFlow(@AuthenticationPrincipal Jwt jwt) throws Exception { 
        
        String baseUrl = xsuaaBindindInformation.getUaaUrl();
        String clientId = "Client ID of service you want to exchange the token for. Should have been injected into your environment.";
        String clientSecret = "Client secret of service you want to exchange the token for. Should have been injected into your environment.";
        
        Jwt userToken = xsuaaTokenFlows.userTokenFlow(URI.create(baseUrl))
        		.token(jwt)
                .client(clientId)
                .secret(clientSecret)
                .execute();
 
        logger.info("Got the exchanged token for 3rd party service (clientId: {}) : {}", clientId, userToken.getTokenValue());
        logger.info("You can now call the 3rd party service passing the exchanged token value: {}. ", userToken.getTokenValue());
                
        return userToken;
    }
}
