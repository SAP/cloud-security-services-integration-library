package com.sap.cloud.security.spring.autoconfig;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SecurityContextAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withPropertyValues("sap.spring.security.hybrid.sync_securitycontext:true")
            .withConfiguration(AutoConfigurations.of(SecurityContextAutoConfiguration.class));

    @Test
    void autoConfigurationActive() {
        runner.run(context -> assertNotNull(context.getBean("methodInvokingFactoryBean")));
    }

    @Test
    void autoConfigurationDisabledByProperty() {
        runner.withPropertyValues("sap.spring.security.hybrid.auto:false").run((context) -> assertFalse(context.containsBean("methodInvokingFactoryBean")));
    }
}