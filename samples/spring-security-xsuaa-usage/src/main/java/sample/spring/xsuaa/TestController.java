package sample.spring.xsuaa;

import java.util.HashMap;
import java.util.Map;

import com.sap.cloud.security.xsuaa.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

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
     * Returns some generic information from the JWT token.
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

}
