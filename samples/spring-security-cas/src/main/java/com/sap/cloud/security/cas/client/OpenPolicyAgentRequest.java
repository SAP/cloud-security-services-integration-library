package com.sap.cloud.security.cas.client;

import java.util.HashMap;
import java.util.Map;

/**
 * TODO: extract as library
 */
public class OpenPolicyAgentRequest {
    private String casUserId = "user";
    private String casAction;
    private String casResource;


    private Map<String, Object> input = new HashMap<>();

    public OpenPolicyAgentRequest(String userId) {
        this.casUserId = userId;
    }

    public OpenPolicyAgentRequest withAction(String action) {
        this.casAction = action;
        return this;
    }

    public OpenPolicyAgentRequest withResource(String resource) {
        this.casResource = resource;
        return this;
    }

    public OpenPolicyAgentRequest withAttribute(String attributeName, Object attributeValue) {
        if (attributeName != null) {
            input.put(attributeName, attributeValue);
        }
        return this;
    }

    public OpenPolicyAgentRequest withUserAttributes(Map<String, String> userAttributes) {
        // TODO
        return this;
    }

    public OpenPolicyAgentRequest withAttributes(String... attributeExpressions) {
        for (String attribute : attributeExpressions) {
            String[] parts = attribute.split("=");
            String value = parts[1];
            if(value.matches("[0-9]+")) {
                withAttribute(parts[0], Integer.parseInt(value));
            } else {
                try {
                    withAttribute(parts[0], Double.parseDouble(value));
                } catch (NumberFormatException ex) {
                    withAttribute(parts[0], value);
                }
            }
        }
        return this;
    }

    /**
     * Required for HttpMessageConverter.
     * @return
     */
    public Map<String, Object> getInput() {
        DefaultAttributes casAttributes = new DefaultAttributes(casUserId, null, casAction, casResource);
        input.put("$cas", casAttributes.getInput());
        return this.input;
    }

    private static class DefaultAttributes {
        private Map<String, Object> cas = new HashMap<>();

        private static final String USER_ID = "userID";
        //private static final String ZONE_ID = "zoneId";
        private static final String ACTION = "action";
        private static final String RESOURCE = "resource";

        DefaultAttributes(String sapUserId, String sapZoneId, String action, String resource) {
            if (sapUserId != null) {
                cas.put(USER_ID, sapUserId);
            }
            if (action != null) {
                cas.put(ACTION, action);
            }
            if (resource != null) {
                cas.put(RESOURCE, resource);
            }
        }

        /**
         * Required for HttpMessageConverter.
         * @return
         */
        public Map<String, Object> getInput() {
            return this.cas;
        }
    }
}