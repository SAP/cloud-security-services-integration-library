package com.sap.cloud.security.cas.client.api;

public interface AdcServiceResponse {
    boolean getResult();

    /**
     * // TODO remove to dedicated interface
     * For Spring usage.
     * @param result
     */
    void setResult(boolean result);

    void setResult(String jsonContent);
}
