package sample.spring.xsuaa;

import java.util.HashMap;
import java.util.Map;

import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sap.cloud.security.xsuaa.token.Token;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_USER_NAME;

@RestController
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    /**
     * A (fake) data layer showing global method security features of Spring Security
     * in combination with tokens from XSUAA.
     */
    private DataService dataService;

    @Autowired
    public TestController(XsuaaTokenFlows tokenFlows, DataService dataService) {
        this.dataService = dataService;
    }

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
        logger.info(token.toString());

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
        logger.info(jwt.toString());

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
        return dataService.readSensitiveData();
    }

}
