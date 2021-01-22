package com.sap.cloud.security.autoconfig;

import com.sap.cloud.security.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.token.authentication.XsuaaTokenAuthorizationConverter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class HybridAuthorizationAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            //.withPropertyValues("xsuaa.xsappname2:theAppName")
            .withUserConfiguration(XsuaaServiceConfiguration.class)
            .withConfiguration(AutoConfigurations.of(HybridAuthorizationAutoConfiguration.class));

    @Test
    void autoConfigurationActive() {
        runner.run(context -> {
                    assertNotNull(context.getBean(XsuaaTokenAuthorizationConverter.class));
                    assertNotNull(context.getBean("xsuaaAuthConverter", Converter.class));
                });
    }

    @Test
    void autoConfigurationActiveInclProperties() {
        runner.withPropertyValues("sap.spring.security.hybrid.auto:true").run((context) -> {
            assertNotNull(context.getBean(XsuaaTokenAuthorizationConverter.class));
        });
    }

    @Test
    public void autoConfigurationDisabledByProperty() {
        runner.withPropertyValues("sap.spring.security.hybrid.auto:false").run((context) -> {
            assertFalse(context.containsBean("xsuaaAuthConverter"));
        });
    }

    @Test
    public void userConfigurationCanOverrideDefaultBeans() {
        runner.withUserConfiguration(UserConfiguration.class)
                .run((context) -> {
                    assertFalse(context.containsBean("xsuaaAuthConverter"));
                    assertNotNull(context.getBean("customXsuaaAuthConverter", XsuaaTokenAuthorizationConverter.class));
                });
    }

    @Configuration
    public static class UserConfiguration {

        @Bean
        public XsuaaTokenAuthorizationConverter customXsuaaAuthConverter() {
            return new XsuaaTokenAuthorizationConverter("appId") {
                @Override
                public AbstractAuthenticationToken convert(Jwt jwt) {
                    return null;
                }
            };
        }
    }

}
