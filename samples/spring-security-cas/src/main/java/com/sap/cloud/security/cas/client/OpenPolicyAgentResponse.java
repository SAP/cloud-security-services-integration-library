package com.sap.cloud.security.cas.client;

/**
 * TODO: extract as library
 */
public class OpenPolicyAgentResponse {

    private boolean result = false;
    public static OpenPolicyAgentResponse DEFAULT = new OpenPolicyAgentResponse();


    public OpenPolicyAgentResponse() {

    }


    public boolean getResult() {
        return this.result;
    }

    public void setResult(boolean result) {
        this.result = result;
    }

}