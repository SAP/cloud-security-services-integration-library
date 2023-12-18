package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.ServiceConstants;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ConfigurationUtil {
    static void assertXsuaaConfigsAreEqual(XsuaaServiceConfiguration xsuaaConfig, OAuth2ServiceConfiguration oauthConfig) {
        assertEquals(oauthConfig.getClientId(), xsuaaConfig.getClientId());
        assertEquals(oauthConfig.getClientSecret(), xsuaaConfig.getClientSecret());
        assertEquals(oauthConfig.getProperty(ServiceConstants.XSUAA.UAA_DOMAIN), xsuaaConfig.getProperty(ServiceConstants.XSUAA.UAA_DOMAIN));
        assertEquals(oauthConfig.getProperty(ServiceConstants.XSUAA.APP_ID), xsuaaConfig.getProperty(ServiceConstants.XSUAA.APP_ID));
        assertEquals(oauthConfig.getProperty(ServiceConstants.NAME), xsuaaConfig.getName());
        assertEquals(oauthConfig.getProperty(ServiceConstants.SERVICE_PLAN), xsuaaConfig.getPlan());
    }
}
