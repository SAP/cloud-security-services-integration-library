package com.sap.cloud.security.cas.client;

import java.util.HashMap;
import java.util.Map;

/**
 * TODO: extract as library
 */
public class OpenPolicyAgentRequest {
    private static final String USER = "user";
    private static final String ACTION = "action";
    private static final String RESOURCE = "resource";

    private Map<String, Object> input = new HashMap<>();

    public OpenPolicyAgentRequest(String uniqueUserId) {
        input.put(USER, uniqueUserId);
    }

    public OpenPolicyAgentRequest withAction(String action) {
        if (action != null) {
            input.put(ACTION, action);
        }
        return this;
    }

    public OpenPolicyAgentRequest withResource(String resource) {
        if (resource != null) {
            input.put(RESOURCE, resource);
        }
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