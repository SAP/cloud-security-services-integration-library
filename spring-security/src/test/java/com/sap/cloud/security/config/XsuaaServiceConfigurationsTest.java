package com.sap.cloud.security.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertEquals;


public class XsuaaServiceConfigurationsTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner();

    @EnableConfigurationProperties(XsuaaServiceConfigurations.class)
    static class EnablePropertiesConfiguration {
    }

    @Test
    void configuresXsuaaServiceConfiguration() {
        runner.withUserConfiguration(EnablePropertiesConfiguration.class)
                .withPropertyValues("sap.security.services.xsuaa[0].url:http://localhost", "sap.security.services.xsuaa[0].uaadomain:localhost", "sap.security.services.xsuaa[0].clientid:cid1")
                .withPropertyValues("sap.security.services.xsuaa[1].url:http://localhost", "sap.security.services.xsuaa[1].uaadomain:localhost", "sap.security.services.xsuaa[1].clientid:cid2")
                .run(context -> {
                    assertEquals("cid1", context.getBean(XsuaaServiceConfigurations.class).getXsuaaServices().get(0).getClientId());
                    assertEquals("cid2", context.getBean(XsuaaServiceConfigurations.class).getXsuaaServices().get(1).getClientId());
                });
    }
}
