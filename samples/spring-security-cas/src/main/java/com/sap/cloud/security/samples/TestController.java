package com.sap.cloud.security.samples;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
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
    @PreAuthorize("onAction('read')") // grant rule <action> on any resource
    @GetMapping(value = "/read")
    public String read() {
        return "Read-protected method called!";
    }

    @PreAuthorize("onResource('SalesOrders')") // grant rule * on <resource>
    @GetMapping(value = "/salesOrders")
    public String salesOrders() {
        return "Protected SalesOrder resource accessed!";
    }

    @PreAuthorize("onResourceAction('SalesOrders', 'read')") // grant rule <action> on <resource>
    @GetMapping(value = "/readSalesOrders")
    public String readSelectedSalesOrder() {
        return "Read-protected SalesOrder resource accessed!";
    }

    @PreAuthorize("onAction('read', 'Country='+#country)") // grant rule <action> on any resource where Country = 'DE'
    @GetMapping(value = "/readByCountry/{country}")
    public String readResourcesInCountry(@PathVariable String country) {
        return "Read-protected resource in country = " + country + " accessed!";
    }

    @PreAuthorize("onResourceAction('SalesOrders', 'read', 'Country='+#country,'SalesID='+#id)")  // grant rule <action> on <resource> where Country = {country} AND SalesID = {id}
    @GetMapping(value = "/readSalesOrderById/{country}/{id}")
    public String readSelectedSalesOrder(@PathVariable String country, @PathVariable String id) {
        return "Read-protected SalesOrder with attributes country = " + country +  " and id " + id + " accessed!";
    }

}