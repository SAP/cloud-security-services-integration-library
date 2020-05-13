package com.sap.cloud.security.cas.client;


import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AdcServiceResponseDefaultTest {

    @Test
    public void withJson_true() {
        AdcServiceResponse response = new AdcServiceResponseDefault();

        response.setResult("{\"decision_id\": \"25d452d1-6a92-4a95-a8b8-8f9bd68ca9dd\",\"result\":true}");

        assertEquals(true, response.getResult());
    }

    @Test
    public void withJson_false() {
        AdcServiceResponse response = new AdcServiceResponseDefault();

        response.setResult("{\"decision_id\": \"25d452d1-6a92-4a95-a8b8-8f9bd68ca9dd\",\"result\":false}");

        assertEquals(false, response.getResult());
    }
}
