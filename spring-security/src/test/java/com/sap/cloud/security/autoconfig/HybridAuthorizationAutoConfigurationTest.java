package com.sap.cloud.security.autoconfig;

import com.sap.cloud.security.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.token.authentication.XsuaaTokenAuthorizationConverter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.core.convert.converter.Converter;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class HybridAuthorizationAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(HybridAuthorizationAutoConfiguration.class));

    @Test
    void configuresJwtDecoder() {
        runner.withUserConfiguration(XsuaaServiceConfiguration.class)
                //.withPropertyValues("xsuaa.xsappname2:theAppName")
                .run(context -> {
                    assertNotNull(context.getBean(XsuaaTokenAuthorizationConverter.class));
                    assertNotNull(context.getBean("xsuaaAuthConverter", Converter.class));
                });
    }

}
