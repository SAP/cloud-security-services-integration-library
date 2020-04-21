package com.sap.cloud.security.cas.client;

import org.json.JSONObject;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * TODO: extract as library
 */
public class ADCServiceRequest {
    private String casUserId = "user";
    private String casAction;
    private String casResource;
    private Map<String, Object> appAttributes = new HashMap();
    private Map<String, String> userAttributes = new HashMap();
    private static Set<String> claimsToBeIgnored = new HashSet() {{
        add("aud");
        add("iss");
        add("exp");
        add("cid");
        add("sub");
    }};

    private Map<String, Object> input = new HashMap<>();

    public ADCServiceRequest(String userId) {
        this.casUserId = userId;
    }

    public ADCServiceRequest withAction(String action) {
        this.casAction = action;
        return this;
    }

    public ADCServiceRequest withResource(String resource) {
        this.casResource = resource;
        return this;
    }

    public ADCServiceRequest withAttribute(String attributeName, Object attributeValue) {
        if (attributeName != null) {
            appAttributes.put(attributeName, attributeValue);
        }
        return this;
    }

    public ADCServiceRequest withUserAttributes(Map<String, String> userAttributes) {
        this.userAttributes.putAll(userAttributes);
        return this;
    }

    public ADCServiceRequest withAttributes(String... attributeExpressions) {
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
     * Required for Spring HttpMessageConverter.
     * @return
     */
    public Map<String, Object> getInput() {
        DefaultAttributes casAttributes = new DefaultAttributes(casUserId, null, casAction, casResource);

        input.put("$cas", casAttributes.getAsMap());

        if(!userAttributes.isEmpty()) {
            claimsToBeIgnored.forEach((claimToBeIgnored)->userAttributes.remove(claimToBeIgnored));
            input.put("$user", userAttributes);
        }

        if(!appAttributes.isEmpty()) {
            input.put("$app", appAttributes);
        }

        return this.input;
    }

    public String asInputJson() {
        JSONObject inputJsonObject = new JSONObject();
        inputJsonObject.put("input", getInput());
        return inputJsonObject.toString();
    }

    private static class DefaultAttributes {
        private Map<String, String> cas = new HashMap<>();

        private static final String USER_ID = "userId";
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
        public Map<String, String> getAsMap() {
            return this.cas;
        }

    }
}