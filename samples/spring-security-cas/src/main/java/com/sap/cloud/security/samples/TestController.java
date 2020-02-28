package com.sap.cloud.security.samples;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping(value = "/")  //Health check, not secured
    public String healthCheck() {

        return "OK";
    }

    @GetMapping(value = "/authenticate") // redirects to login page
    public String secured(@AuthenticationPrincipal OidcUser principal) {
        String name = principal.getGivenName();

        if (name == null) {
            name = principal.getEmail();
        }
        return "Congratulation, " + name
                + "! You just logged in successfully.";
    }

    /**
     * An endpoint showing how to use Spring method security.
     * Only if the request principal has the given privilege he/she is allowed to
     * access the method. Otherwise a 403 error will be returned.
     */
    @GetMapping(value = "/authorized")
    @PreAuthorize("hasRule('read', 'SalesOrders')") // grant rule <action> on <resource>
    public String callMethodRemotely(@AuthenticationPrincipal OidcUser principal) {
        return "Read-protected method called! " + principal.getGivenName();
    }

}