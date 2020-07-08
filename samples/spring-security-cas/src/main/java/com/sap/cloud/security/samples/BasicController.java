package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.AdcException;
import com.sap.cloud.security.cas.client.AdcService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.HttpStatus.OK;

@RestController
public class BasicController {

    @Autowired
    AdcService adcService;

    @Value("${ADC_URL:http://localhost:8181}")
    private String adcUrl;

    @GetMapping(value = "/health")  // health check, not secured
    @ResponseStatus(OK)
    public String healthCheck() {
        if(!adcService.ping()) { // TODO this can be done as part of health check
            throw new AdcException("Application is not healthy: ADC Service is not up and running.");
        }
        return "OK";
    }

    @GetMapping(value = "/authenticate") // redirects to login page
    public String secured(@AuthenticationPrincipal OidcUser principal) {
        String name = principal.getName();
        if (name == null) {
            name = principal.getEmail();
        }
        return "Congratulation, " + name
                + "! You just logged in successfully (zoneId : " + principal.getAttribute("zid") + ").";
    }

    @PreAuthorize("forAction('read')") // grant rule <action> on any resource
    @GetMapping(value = "/read")
    public String authorizedRead() {
        return "Read-protected method called!";
    }

}