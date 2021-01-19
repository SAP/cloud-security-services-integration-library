package com.sap.cloud.security.autoconfig;

import com.sap.cloud.security.config.OAuth2ServiceConfigurationProperties;
import com.sap.cloud.security.config.Service;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConditionalOnProperty("identity.url") // TODO update to domain
@ConfigurationProperties("identity")
public class IdentityServiceConfiguration extends OAuth2ServiceConfigurationProperties {

    /**
     * Creates a new instance to map configuration of a dedicated identity service.
     *
     */
    public IdentityServiceConfiguration() {
        super(Service.IAS);
    }
}
