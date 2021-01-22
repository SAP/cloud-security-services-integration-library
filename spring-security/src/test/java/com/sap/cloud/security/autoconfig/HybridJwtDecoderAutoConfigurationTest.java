package com.sap.cloud.security.autoconfig;

import com.sap.cloud.security.token.authentication.HybridJwtDecoder;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import static org.junit.jupiter.api.Assertions.*;

public class HybridJwtDecoderAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withPropertyValues("sap.security.services.xsuaa.url:http://localhost", "sap.security.services.xsuaa.uaadomain:localhost", "sap.security.services.xsuaa.clientid:cid",
                    "sap.security.services.identity.url:http://localhost", "sap.security.services.identity.clientid:cid")
            .withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class));

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
    public void autoConfigurationDisabledByProperty() {
        runner.withPropertyValues("sap.spring.security.hybrid.auto:false").run((context) -> {
            assertFalse(context.containsBean("hybridJwtDecoder"));
        });
    }

    @Test
    public void userConfigurationCanOverrideDefaultBeans() {
        runner.withUserConfiguration(UserConfiguration.class)
                .run((context) -> {
                    assertFalse(context.containsBean("hybridJwtDecoder"));
                    assertNotNull(context.getBean("customJwtDecoder", NimbusJwtDecoder.class));
                });
    }

    @Configuration
    public static class UserConfiguration {

        @Bean
        public JwtDecoder customJwtDecoder() {
            return NimbusJwtDecoder.withJwkSetUri("http://localhost:8080/uaa/oauth/token_keys").build();
        }
    }

}
