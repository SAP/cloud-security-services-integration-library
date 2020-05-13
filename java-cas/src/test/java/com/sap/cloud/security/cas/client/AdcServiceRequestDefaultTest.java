package com.sap.cloud.security.cas.client;


import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AdcServiceRequestTest {

    @Test
    public void withAllRequiredCasAttributes() {
        DefaultAdcServiceRequest request = new DefaultAdcServiceRequest("uid");
        assertEquals("{\"input\":{\"$cas\":{\"userId\":\"uid\"}}}", request.asInputJson());
    }

    @Test
    public void withAllCasAttributes() {
        DefaultAdcServiceRequest request = new DefaultAdcServiceRequest("uid");
        request.withAction("theAction");
        request.withResource("theResource");
        assertEquals("{\"input\":{\"$cas\":{\"resource\":\"theResource\",\"action\":\"theAction\",\"userId\":\"uid\"}}}", request.asInputJson());
    }

    @Test
    public void withAttributes() {
        DefaultAdcServiceRequest request = new DefaultAdcServiceRequest("uid");
        request.withAttribute("attr", "attrValue");
        request.withAttribute("attr_double", 1.234);
        request.withAttribute("attr_integer", 567);
        assertEquals("{\"input\":{\"$cas\":{\"userId\":\"uid\"},\"$app\":{\"attr\":\"attrValue\",\"attr_double\":1.234,\"attr_integer\":567}}}", request.asInputJson());
    }

    @Test
    public void withUserAttributes() {
        DefaultAdcServiceRequest request = new DefaultAdcServiceRequest("uid");
        Map<String, String> userAttributes = new HashMap() {{
            put("sub", "ignore");
            put("use", "useThis");
        }};
        request.withUserAttributes(userAttributes);
        assertEquals("{\"input\":{\"$cas\":{\"userId\":\"uid\"},\"$user\":{\"use\":\"useThis\"}}}", request.asInputJson());
    }
}
