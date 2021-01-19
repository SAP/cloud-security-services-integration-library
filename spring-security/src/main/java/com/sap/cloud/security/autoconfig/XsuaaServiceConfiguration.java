package com.sap.cloud.security.autoconfig;

import com.sap.cloud.security.config.OAuth2ServiceConfigurationProperties;
import com.sap.cloud.security.config.Service;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConditionalOnProperty("xsuaa.url")
@ConfigurationProperties("xsuaa")
public class XsuaaServiceConfiguration extends OAuth2ServiceConfigurationProperties {

    /**
     * Creates a new instance to map configuration of a dedicated identity service.
     *
     */
    public XsuaaServiceConfiguration() {
        super(Service.XSUAA);
    }
}