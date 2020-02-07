package com.sap.cloud.security.cas.client;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TODO: extract as library
 */
public class OpenPolicyAgentRequest {
    private static final String USER = "user";
    private static final String ACTION = "action";

    private Map<String, Object> input = new HashMap<>();

    // TODO!!!! hard codes to user Alice
    public OpenPolicyAgentRequest(String policy, String uniqueUserId) {
        input.put(USER, /*uniqueUserId +*/ "Alice_" + policy);
    }

    public OpenPolicyAgentRequest withAction(String action) {
        input.put(ACTION, action);
        return this;
    }

    /*public static class Attribute {
        public final String name;
        public final List<String> values;

        public Attribute(String name, String... values) {
            this.name = name;
            this.values = Arrays.asList(values);
        }
    }

    /**
     * Required for HttpMessageConverter.
     * @return
     */
    public Map<String, Object> getInput() {
        return this.input;
    }

}