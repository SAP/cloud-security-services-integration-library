package sample.spring.security;

import java.util.HashMap;
import java.util.Map;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    /**
     * A (fake) data layer showing global method security features of Spring Security
     * in combination with tokens from XSUAA.
     */
    private DataService dataService;

    @Autowired
    public TestController(DataService dataService) {
        this.dataService = dataService;
    }

    /**
     * Returns the detailed information of the XSUAA JWT token.
     * Uses a Token retrieved from the security context of Spring Security.
     *
     * @param token the XSUAA token from the request injected by Spring Security.
     * @return the requested address.
     */
    @GetMapping("/sayHello")
    public Map<String, String> sayHello(@AuthenticationPrincipal Token token) {

        logger.info("Got the Xsuaa token: {}", token.getTokenValue());
        logger.info(token.toString());

        Map<String, String> result = new HashMap<>();
        result.put("grant type", token.getClaimAsString(TokenClaims.XSUAA.GRANT_TYPE));
        result.put("client id", token.getClientId());
        //result.put("subaccount id", token.getSubaccountId());
        result.put("zone id", token.getZoneId());
        //result.put("logon name", token.getLogonName());
        result.put("family name", token.getClaimAsString(TokenClaims.FAMILY_NAME));
        result.put("given name", token.getClaimAsString(TokenClaims.GIVEN_NAME));
        result.put("email", token.getClaimAsString(TokenClaims.EMAIL));
        result.put("scopes", String.valueOf(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)));

        return result;
    }

    /**
     * An endpoint showing how to use Spring method security.
     * Only if the request principal has the given scope will the
     * method be called. Otherwise a 403 error will be returned.
     */
    @GetMapping("/method")
    @PreAuthorize("hasAuthority('Read') or hasAuthority('GROUP_READ')")
    public String callMethodRemotely() {
        return dataService.readSensitiveData();
    }

}
