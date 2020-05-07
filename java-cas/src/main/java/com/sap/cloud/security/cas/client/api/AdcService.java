package com.sap.cloud.security.cas.client.api;


public interface AdcService {
    AdcServiceResponse isUserAuthorized(AdcServiceRequest request);

    boolean ping();
}
