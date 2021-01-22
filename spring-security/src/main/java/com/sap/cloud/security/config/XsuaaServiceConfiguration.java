package com.sap.cloud.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("sap.security.services.xsuaa")
public class XsuaaServiceConfiguration extends OAuth2ServiceConfigurationProperties {

    /**
     * Creates a new instance to map configuration of a dedicated identity service.
     *
     */
    public XsuaaServiceConfiguration() {
        super(Service.XSUAA);
    }
}