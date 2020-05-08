package com.sap.cloud.security.cas.client;

public interface AdcServiceResponse {
    boolean getResult();

    /**
     * // TODO remove to dedicated interface
     * For Spring usage.
     */
    //void setResult(boolean result);

    void setResult(String jsonContent);
}
