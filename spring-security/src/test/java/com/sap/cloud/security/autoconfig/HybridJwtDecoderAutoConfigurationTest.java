package com.sap.cloud.security.autoconfig;

import com.sap.cloud.security.token.authentication.HybridJwtDecoder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HybridJwtDecoderAutoConfigurationTest {
    private final List<String> properties = new ArrayList<>();
    private WebApplicationContextRunner runner;

    @BeforeEach
    void setup() {
        properties.add("sap.security.services.xsuaa.url:http://localhost");
        properties.add("sap.security.services.xsuaa.uaadomain:localhost");
        properties.add("sap.security.services.xsuaa.xsappname:theAppName");
        properties.add("sap.security.services.xsuaa.clientid:cid");
        properties.add("sap.security.services.identity.url:http://localhost");
        properties.add("sap.security.services.identity.clientid:cid");

        runner = new WebApplicationContextRunner()
                .withPropertyValues(properties.toArray(new String[6]))
                .withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class));
    }

    @Test
    void autoConfigurationActive() {
        runner.run(context -> {
                    assertNotNull(context.getBean("hybridJwtDecoder", HybridJwtDecoder.class));
                });
    }

    @Test
    void autoConfigurationActiveInclProperties() {
        runner.withPropertyValues("sap.spring.security.hybrid.auto:true").run((context) -> {
            assertNotNull(context.getBean(HybridJwtDecoder.class));
        });
    }

    @Test
    void autoConfigurationDisabledByProperty() {
        runner.withPropertyValues("sap.spring.security.hybrid.auto:false").run((context) -> {
            assertFalse(context.containsBean("hybridJwtDecoder"));
        });
    }

    @Test
    void autoConfigurationDisabledForMultipleXsuaaServices() {
        List<String> mt_properties = new ArrayList<>();
        WebApplicationContextRunner mt_runner;

        mt_properties.add("sap.security.services.xsuaa[0].url:http://localhost");
        mt_properties.add("sap.security.services.xsuaa[0].uaadomain:localhost");
        mt_properties.add("sap.security.services.xsuaa[0].xsappname:theAppName");
        mt_properties.add("sap.security.services.xsuaa[0].clientid:cid");
        mt_properties.add("sap.security.services.identity.url:http://localhost");
        mt_properties.add("sap.security.services.identity.clientid:cid");

        mt_runner = new WebApplicationContextRunner()
                .withPropertyValues(mt_properties.toArray(new String[6]))
                .withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class));

        mt_runner.run(context -> {
            assertFalse(context.containsBean("hybridJwtDecoder"));
            assertNotNull(context.getBean("hybridJwtDecoderMultiXsuaaServices", HybridJwtDecoder.class));
        });
    }

    @Test
    void userConfigurationCanOverrideDefaultBeans() {
        runner.withUserConfiguration(UserConfiguration.class)
                .run((context) -> {
                    assertFalse(context.containsBean("hybridJwtDecoder"));
                    assertNotNull(context.getBean("customJwtDecoder", NimbusJwtDecoder.class));
                });
    }

    @Configuration
    static class UserConfiguration {

        @Bean
        public JwtDecoder customJwtDecoder() {
            return NimbusJwtDecoder.withJwkSetUri("http://localhost:8080/uaa/oauth/token_keys").build();
        }
    }

}
