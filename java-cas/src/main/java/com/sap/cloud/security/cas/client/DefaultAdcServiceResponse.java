package com.sap.cloud.security.cas.client;

import com.sap.cloud.security.cas.client.api.AdcServiceResponse;
import org.json.JSONObject;

/**
 * This {@code AdcServiceResponse} implementation makes use of org.json Json Parser
 * to extract the result from ADC response.
 */
public class DefaultAdcServiceResponse implements AdcServiceResponse {

    private boolean result = false;
    public static AdcServiceResponse DEFAULT = new DefaultAdcServiceResponse();
    private static final String ADC_RESULT_KEY = "result";


    public DefaultAdcServiceResponse() {
    }

    public DefaultAdcServiceResponse(String jsonContent) {
        this.setResult(jsonContent);
    }

    @Override
    public boolean getResult() {
        return this.result;
    }

     @Override
    public void setResult(boolean result) {
        this.result = result;
    }

    /**
     *
     * @param jsonContent
     */
    @Override
    public void setResult(String jsonContent) {
        JSONObject jsonObject = new JSONObject(jsonContent);
        if(jsonObject.has(ADC_RESULT_KEY)) {
            this.result = jsonObject.getBoolean(ADC_RESULT_KEY);
        }
    }

}