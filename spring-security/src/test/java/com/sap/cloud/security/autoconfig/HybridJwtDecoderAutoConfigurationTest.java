package com.sap.cloud.security.autoconfig;

import com.sap.cloud.security.token.authentication.HybridJwtDecoder;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class HybridJwtDecoderAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(HybridIdentityServicesAutoConfiguration.class));

    @Test
    void configuresJwtDecoder() {
        runner.withPropertyValues("xsuaa.url:http://localhost", "xsuaa.uaadomain:localhost", "xsuaa.clientid:cid",
                        "identity.url:http://localhost", "identity.clientid:cid")
                .run(context -> {
                    assertNotNull(context.getBean(HybridJwtDecoder.class));
                });
    }

}
