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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    //    /**
    //     * The injected factory for XSUAA token flows.
    //     */
    //    @Autowired
    //    private XsuaaTokenFlows xsuaaTokenFlows;
    //
    //    /**
    //     * The injected XSUAA service binding information from environment.
    //     */
    //    @Autowired
    //    private XsuaaServiceBindings xsuaaServiceBindings;

    /**
     * A (fake) data layer showing global method security features of Spring Security
     * in combination with tokens from XSUAA.
     */
    @Autowired
    private DataService dataService;

    /**
     * Returns the address of the address service.
     * Uses a JWT retrieved from the security context of Spring Security.
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
     * The result is, that the {@link DataService#readData()} method
     * will only be called if the proper scopes are available.
     *
     * @return the data read from the {@link DataService} or fails
     * with an access denied error.
     * @see {@link DataService}.
     */
    @GetMapping(value = "/v1/readData")
    public String readFromDataService() {
        return dataService.readData();
    }

    /**
     * Write case showing method level security.
     */
    @PostMapping(value = "/v1/writeData")
    public void writeToDataService() {
        logger.info("Try writing data.");
        dataService.writeData("Spring Rocks!");
    }

    //    /**
    //     * REST endpoint showing how to fetch a Client Credentials Token from XSUAA using the
    //     * XsuaaTokenFlows bean injected by Spring and exposed by the (new) XSUAA client library
    //     * implementation.
    //     * @param jwt - the Jwt as a result of authentication.
    //     * @return the Client Credentials Token fetched from XSUAA. Don't do this in production!
    //     * @throws Exception in case of any errors.
    //     */
    //    @GetMapping(value = "/v2/clientCredentialsToken")
    //    public Jwt fetchClientCredentialsToken(@AuthenticationPrincipal Jwt jwt) throws Exception {
    //
    //        Map<String, XsuaaBindingInfo> bindings = xsuaaServiceBindings.getXsuaaBindingInformation();
    //
    //        XsuaaBindingInfo xsuaaBindingInfo = bindings.get("xsuaa-authentication");
    //
    //        String baseUrl = xsuaaBindingInfo.getCredentials().getBaseUrl();
    //        String clientId = xsuaaBindingInfo.getCredentials().getClientId();
    //        String clientSecret = xsuaaBindingInfo.getCredentials().getClientSecret();
    //
    //        Jwt ccfToken = xsuaaTokenFlows.clientCredentialsTokenFlow(URI.create(baseUrl))
    //                .client(clientId)
    //                .secret(clientSecret)
    //                .execute();
    //
    //        logger.info("CCF Token: {}", ccfToken.getTokenValue());
    //
    //        return ccfToken;
    //    }
    //
    //    /**
    //     * Prints the XSUAA service instance binding information from environment.
    //     * @param jwt - the Jwt as a result of authentication.
    //     * @return the XSUAA service instance binding information from environment.
    //     * @throws Exception in case of any errors.
    //     */
    //    @GetMapping(value = "/v2/printXsuaaBindingInformation")
    //    public String printXsuaaServiceBindingsInformation(@AuthenticationPrincipal Jwt jwt) throws Exception {
    //
    //        Map<String, XsuaaBindingInfo> bindings = xsuaaServiceBindings.getXsuaaBindingInformation();
    //
    //        ObjectMapper mapper = new ObjectMapper();
    //        String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(bindings);
    //        logger.info("Parsed XSUAA Configurations from Environment: ");
    //        logger.info(json);
    //        return json;
    //    }
}
