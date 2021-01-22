package com.sap.cloud.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties("sap.security.services")
public class XsuaaServiceConfigurations {
    @NestedConfigurationProperty
    private List<XsuaaServiceConfiguration> xsuaa = new ArrayList<>();

    public List<XsuaaServiceConfiguration> getConfigurations() {
        return this.xsuaa;
    }

    public void setXsuaa(List<XsuaaServiceConfiguration> xsuaa) {
        this.xsuaa = xsuaa;
    }

}
