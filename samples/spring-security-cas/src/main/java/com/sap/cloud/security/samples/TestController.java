package com.sap.cloud.security.samples;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class TestController {

    //Health check, not secured
    @RequestMapping(value = "/", method = RequestMethod.GET)
    public ResponseEntity<String> healthCheck() {

        return new ResponseEntity<String>("OK", HttpStatus.OK);
    }

    //Secured resource; redirects to login page
    @RequestMapping(value = "/secured", method = RequestMethod.GET)
    public ResponseEntity<String> secured() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthenticationToken oauthAuth = (OAuth2AuthenticationToken)auth;

        OidcUser user = (OidcUser)oauthAuth.getPrincipal();
        String name = user.getClaim("given_name");

        if(name==null) {
            name = user.getClaim("email");
        }

        return new ResponseEntity<String>("Congratulation, " + name//SecurityContext.getUserInfo().getGivenName()
                + "! You just logged in successfully."
                , HttpStatus.OK);
    }
}
