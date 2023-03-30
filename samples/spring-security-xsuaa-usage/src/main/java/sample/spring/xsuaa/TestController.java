/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa;

import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.token.Token;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_USER_NAME;

@RestController
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    /**
     * The injected factory for XSUAA token tokenflows.
     */
    private final XsuaaTokenFlows tokenFlows;

    /**
     * A (fake) data layer showing global method security features of Spring Security
     * in combination with tokens from XSUAA.
     */
    private final DataService dataService;

    @Autowired
    public TestController(XsuaaTokenFlows tokenFlows, DataService dataService) {
        this.tokenFlows = tokenFlows;
        this.dataService = dataService;
    }

    @GetMapping("/health")
    public String sayHello() { return "I'm alright"; }


    /**
     * Returns the detailed information of the XSUAA JWT token.
     * Uses a Token retrieved from the security context of Spring Security.
     *
     * @param token the XSUAA token from the request injected by Spring Security.
     * @return the requested address.
     */
    @GetMapping("/v1/sayHello")
    public Map<String, String> sayHello(@AuthenticationPrincipal Token token) {

        logger.info("Got the Xsuaa token: {}", token.getAppToken());
        logger.info("{}", token);

        Map<String, String> result = new HashMap<>();
        result.put("grant type", token.getGrantType());
        result.put("client id", token.getClientId());
        result.put("subaccount id", token.getSubaccountId());
        result.put("zone id", token.getZoneId());
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
     */
    @GetMapping("/v2/sayHello")
    public String sayHello(@AuthenticationPrincipal Jwt jwt) {

        logger.info("Got the JWT: {}", jwt);
        logger.info(jwt.getClaimAsString(CLAIM_USER_NAME));
        logger.info("{}", jwt);

        return "Hello Jwt-Protected World!";
    }

    /**
     * An endpoint showing how to use Spring method security.
     * Only if the request principal has the given scope will the
     * method be called. Otherwise a 403 error will be returned.
     */
    @GetMapping("/v1/method")
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
     */
    @GetMapping("/v1/getAdminData")
    public String readFromDataService() {
        return dataService.readSensitiveData();
    }
    
    /**
     * REST endpoint showing how to fetch a client credentials Token from XSUAA using the
     * {@link XsuaaTokenFlows} API.
     * @throws TokenFlowException in case of any errors.
     */
    @GetMapping("/v3/requestClientCredentialsToken")
    public String requestClientCredentialsToken() throws TokenFlowException {

        OAuth2TokenResponse clientCredentialsTokenResponse = tokenFlows.clientCredentialsTokenFlow().execute();
        logger.info("Got the Client Credentials Token: {}", clientCredentialsTokenResponse.getAccessToken());

        return clientCredentialsTokenResponse.getDecodedAccessToken().getPayload();
    }

    /**
     * REST endpoint showing how to exchange an access token from XSUAA for another one intended for another service.
     * This endpoint shows how to use the {@link XsuaaTokenFlows} API.
     * <p>
     * The idea behind a user token exchange is to separate service-specific access scopes into separate tokens.
     * For example, if Service A has scopes specific to its functionality and Service B has other scopes, the intention is
     * that there is no single Jwt token that contains all of these scopes.<br>
     * Rather the intention is to have a Jwt token to call Service A (containing just the scopes of Service A),
     * and another one to call Service B (containing just the scopes of Service B). An application calling Service A and
     * B on behalf of a user therefore has to exchange the user's Jwt token against a token for Service A and B respectively
     * before calling these services. This scenario is handled by the JWT Bearer token flow.
     * <p>
     *
     *
     * @param token - the Jwt as a result of authentication.
     * @throws TokenFlowException in case of any errors.
     */
    @GetMapping("/v3/requestJwtBearerToken")
    public String requestJwtBearerToken(@AuthenticationPrincipal Token token) throws TokenFlowException {
        OAuth2TokenResponse tokenResponse = tokenFlows.jwtBearerTokenFlow()
                .token(token.getAppToken())
                .subdomain(token.getSubdomain())
                .execute();

        logger.info("Got the exchanged token for 3rd party service: {}", tokenResponse);
        logger.info("You can now call the 3rd party service passing the exchanged token value: {}. ", tokenResponse);

        return "<p>The access-token (decoded):</p><p>" + tokenResponse.getDecodedAccessToken().getPayload()
                + "</p><p>The refresh-token: </p><p>" + tokenResponse.getRefreshToken()
                + "</p><p>The access-token (encoded) can be found in the logs 'cf logs spring-security-xsuaa-usage --recent'</p>";
    }

    /**
     * REST endpoint showing how to retrieve an access token for a refresh token from XSUAA using the
     * {@link XsuaaTokenFlows} API.
     * @param jwt - the Jwt as a result of authentication.
     * @param refreshToken - the refresh token an access token is requested
     * @throws TokenFlowException in case of any errors.
     */
    @GetMapping("/v3/requestRefreshToken/{refreshToken}")
    public String requestRefreshToken(@AuthenticationPrincipal Jwt jwt, @PathVariable("refreshToken") String refreshToken) throws TokenFlowException {

        OAuth2TokenResponse refreshTokenResponse = tokenFlows.refreshTokenFlow()
        		.refreshToken(refreshToken)
                .execute();
 
        logger.info("Got the access token for the refresh token: {}", refreshTokenResponse.getAccessToken());
        logger.info("You could now inject this into Spring's SecurityContext, using: SpringSecurityContext.init(...).");

        return refreshTokenResponse.getDecodedAccessToken().getPayload();
    }

}
