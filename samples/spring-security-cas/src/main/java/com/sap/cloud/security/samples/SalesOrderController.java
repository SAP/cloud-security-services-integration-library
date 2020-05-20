package com.sap.cloud.security.samples;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/salesOrders")
public class SalesOrderController {

    /**
     * An endpoint showing how to use Spring method security.
     * Only if the request principal has the given privilege he/she is allowed to
     * access the method. Otherwise a 403 error will be returned.
     */
    @PreAuthorize("forResourceAction('salesOrders', 'read')") // grant rule <action> on <resource>
    @GetMapping
    public String readSelectedSalesOrder() {
        return "Read-protected salesOrders resource accessed!";
    }

    @PreAuthorize("forAction('read', 'CountryCode='+#countryCode)") // grant rule <action> on any resource with <attributeValueMap>
    @GetMapping(value = "/readByCountry/{countryCode}")
    public String readResourcesInCountry(@PathVariable String countryCode) {
        return "Read-protected resource with countryCode = " + countryCode + " accessed!";
    }

    @PreAuthorize("forResourceAction('salesOrders', 'read', 'CountryCode='+#countryCode, 'salesID='+#id)")  // grant rule <action> on <resource> with <attributeValueMap>
    @GetMapping(value = "/readByCountryAndId/{countryCode}/{id}")
    public String readSelectedSalesOrder(@PathVariable String countryCode, @PathVariable String id) {
        return "Read-protected SalesOrder with attributes countryCode = " + countryCode +  " and id " + id + " accessed!";
    }

}