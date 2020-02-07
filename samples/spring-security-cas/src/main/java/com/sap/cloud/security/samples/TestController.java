package com.sap.cloud.security.samples;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
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
    public String secured() {
        String name = getOidcUser().getClaim("given_name");

        if(name==null) {
            name = getOidcUser().getClaim("email");
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
    @PreAuthorize("readAll('read')")
    public String callMethodRemotely() {
        return "Read-protected method called! " + getOidcUser().getClaim("given_name");
    }

    private OidcUser getOidcUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthenticationToken oauthAuth = (OAuth2AuthenticationToken)auth;

       return (OidcUser)oauthAuth.getPrincipal();
    }
}
