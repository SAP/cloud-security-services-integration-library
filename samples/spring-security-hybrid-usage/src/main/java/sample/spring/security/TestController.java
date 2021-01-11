package sample.spring.security;

import java.util.HashMap;
import java.util.Map;

import com.sap.cloud.security.token.AccessToken;
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

        logger.debug("Got the token: {}", token.toString());

        Map<String, String> result = new HashMap<>();
        result.put("client id", token.getClientId());
        result.put("audiences", token.getClaimAsStringList(TokenClaims.AUDIENCE).toString());
        result.put("zone id", token.getZoneId());
        result.put("family name", token.getClaimAsString(TokenClaims.FAMILY_NAME));
        result.put("given name", token.getClaimAsString(TokenClaims.GIVEN_NAME));
        result.put("email", token.getClaimAsString(TokenClaims.EMAIL));

        if(token instanceof AccessToken) {
            //result.put("(Xsuaa) subaccount id", ((AccessToken)token).getSubaccountId());
            result.put("(Xsuaa) scopes", String.valueOf(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)));
            result.put("grant type", token.getClaimAsString(TokenClaims.XSUAA.GRANT_TYPE));
        }
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
