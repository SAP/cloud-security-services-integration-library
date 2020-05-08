package com.sap.cloud.security.cas.client;


public interface AdcService {
    AdcServiceResponse isUserAuthorized(AdcServiceRequest request);

    boolean ping();
}
