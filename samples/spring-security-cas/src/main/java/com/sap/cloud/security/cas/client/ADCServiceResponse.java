package com.sap.cloud.security.cas.client;

import org.json.JSONObject;

/**
 * TODO: extract as library
 */
public class ADCServiceResponse {

    private boolean result = false;
    public static ADCServiceResponse DEFAULT = new ADCServiceResponse();


    public ADCServiceResponse() {
    }

    public ADCServiceResponse(String jsonContent) {
        this.setResult(jsonContent);
    }

    public boolean getResult() {
        return this.result;
    }

    /**
     * For Spring usage.
     * @param result
     */
    public void setResult(boolean result) {
        this.result = result;
    }

    /**
     *
     * @param jsonContent
     */
    public void setResult(String jsonContent) {
        JSONObject jsonObject = new JSONObject(jsonContent);
        this.result = jsonObject.getBoolean("result");
    }

}