package com.sap.cloud.security.xsuaa.client;


import java.util.Map;

public interface ServiceManagerService {

    Map<String, String> getServicePlans();

    Map<String, String> getServiceInstances();

    Map<String, String> getServiceInstancePlans();

}
