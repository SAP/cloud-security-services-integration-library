package com.sap.cloud.security.cas.client;

import org.json.JSONObject;

/**
 * TODO: extract as interface
 */
public class ADCServiceResponse {

    private boolean result = false;
    public static ADCServiceResponse DEFAULT = new ADCServiceResponse();
    private static final String ADC_RESULT_KEY = "result";


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
        if(jsonObject.has(ADC_RESULT_KEY)) {
            this.result = jsonObject.getBoolean(ADC_RESULT_KEY);
        }
    }

}