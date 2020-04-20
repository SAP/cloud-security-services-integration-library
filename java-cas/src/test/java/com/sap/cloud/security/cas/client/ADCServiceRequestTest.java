package com.sap.cloud.security.cas.client;


import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ADCServiceRequestTest {

    @Test
    public void withAllRequiredCasAttributes() {
        ADCServiceRequest request = new ADCServiceRequest("uid");
        assertEquals("{\"input\":{\"$cas\":{\"userId\":\"uid\"}}}", request.getInputJson());
    }

    @Test
    public void withAllCasAttributes() {
        ADCServiceRequest request = new ADCServiceRequest("uid");
        request.withAction("theAction");
        request.withResource("theResource");
        assertEquals("{\"input\":{\"$cas\":{\"resource\":\"theResource\",\"action\":\"theAction\",\"userId\":\"uid\"}}}", request.getInputJson());
    }

    @Test
    public void withAttributes() {
        ADCServiceRequest request = new ADCServiceRequest("uid");
        request.withAttribute("attr", "attrValue");
        request.withAttribute("attr_double", 1.234);
        request.withAttribute("attr_integer", 567);
        assertEquals("{\"input\":{\"$cas\":{\"userId\":\"uid\"},\"$app\":{\"attr\":\"attrValue\",\"attr_double\":1.234,\"attr_integer\":567}}}", request.getInputJson());
    }

    @Test
    public void withUserAttributes() {
        ADCServiceRequest request = new ADCServiceRequest("uid");
        Map<String, String> userAttributes = new HashMap() {{
            put("sub", "ignore");
            put("use", "useThis");
        }};
        request.withUserAttributes(userAttributes);
        assertEquals("{\"input\":{\"$cas\":{\"userId\":\"uid\"},\"$user\":{\"use\":\"useThis\"}}}", request.getInputJson());
    }
}
