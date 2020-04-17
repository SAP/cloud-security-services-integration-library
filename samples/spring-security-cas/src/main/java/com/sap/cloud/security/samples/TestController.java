package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.ADCException;
import com.sap.cloud.security.cas.client.ADCService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

import static org.springframework.http.HttpStatus.OK;

@RestController
public class TestController {

    @Autowired
    ADCService adcService;

    @Value("${OPA_URL:http://localhost:8181}")
    private String adcUrl;

    @GetMapping(value = "/health")  // health check, not secured
    @ResponseStatus(OK)
    public String healthCheck() {
        if(!adcService.ping(URI.create(adcUrl))) { // TODO this can be done as part of health check
            throw new ADCException("Application is not healthy: ADC Service is not up and running.");
        }
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
    @PreAuthorize("forAction('read')") // grant rule <action> on any resource
    @GetMapping(value = "/read")
    public String read() {
        return "Read-protected method called!";
    }

    @PreAuthorize("forResource('salesOrders')") // grant rule * on <resource>
    @GetMapping(value = "/salesOrders")
    public String salesOrders() {
        return "Protected salesOrders resource accessed!";
    }

    @PreAuthorize("forResourceAction('salesOrders', 'read')") // grant rule <action> on <resource>
    @GetMapping(value = "/readSalesOrders")
    public String readSelectedSalesOrder() {
        return "Read-protected salesOrders resource accessed!";
    }

    @PreAuthorize("forAction('read', 'CountryCode='+#countryCode)") // grant rule <action> on any resource with <attributeValueMap>
    @GetMapping(value = "/readByCountry/{countryCode}")
    public String readResourcesInCountry(@PathVariable String countryCode) {
        return "Read-protected resource with countryCode = " + countryCode + " accessed!";
    }

    @PreAuthorize("forResourceAction('salesOrders', 'read', 'CountryCode='+#countryCode, 'salesID='+#id)")  // grant rule <action> on <resource> with <attributeValueMap>
    @GetMapping(value = "/readSalesOrderById/{countryCode}/{id}")
    public String readSelectedSalesOrder(@PathVariable String countryCode, @PathVariable String id) {
        return "Read-protected SalesOrder with attributes countryCode = " + countryCode +  " and id " + id + " accessed!";
    }

}