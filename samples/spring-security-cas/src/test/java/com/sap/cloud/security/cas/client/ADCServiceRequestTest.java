package com.sap.cloud.security.cas.client;

import org.junit.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ADCServiceRequestTest {

    @Test
    public void withAllRequiredCasAttributes() {
        ADCServiceRequest request = new ADCServiceRequest("uid");
        assertEquals("{\"input\":{\"$cas\":{\"userID\":\"uid\"}}}", request.getInputJson());
    }

    @Test
    public void withAllCasAttributes() {
        ADCServiceRequest request = new ADCServiceRequest("uid");
        request.withAction("theAction");
        request.withResource("theResource");
        assertEquals("{\"input\":{\"$cas\":{\"resource\":\"theResource\",\"action\":\"theAction\",\"userID\":\"uid\"}}}", request.getInputJson());
    }

    @Test
    public void withAttributes() {
        ADCServiceRequest request = new ADCServiceRequest("uid");
        request.withAttribute("attr", "attrValue");
        request.withAttribute("attr2", "attrValue2");
        assertEquals("{\"input\":{\"$cas\":{\"userID\":\"uid\"},\"attr\":\"attrValue\",\"attr2\":\"attrValue2\"}}", request.getInputJson());
    }
}
