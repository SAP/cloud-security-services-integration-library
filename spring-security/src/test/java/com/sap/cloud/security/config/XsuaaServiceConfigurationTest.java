package com.sap.cloud.security.config;

import com.sap.cloud.security.config.XsuaaServiceConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.*;


public class XsuaaServiceConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner();

    @EnableConfigurationProperties(XsuaaServiceConfiguration.class)
    static class EnablePropertiesConfiguration {
    }

    @Test
    void configuresXsuaaServiceConfiguration() {
        runner.withUserConfiguration(EnablePropertiesConfiguration.class)
                .withPropertyValues("xsuaa.url:http://localhost", "xsuaa.uaadomain:localhost", "xsuaa.clientid:cid")
                .run(context -> {
                    assertEquals("http://localhost", context.getBean(XsuaaServiceConfiguration.class).getUrl().toString());
                });
    }
}
