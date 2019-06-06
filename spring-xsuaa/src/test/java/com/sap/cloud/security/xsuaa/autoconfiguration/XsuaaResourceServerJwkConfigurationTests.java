package com.sap.cloud.security.xsuaa.autoconfiguration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.sap.cloud.security.xsuaa.XsuaaServiceBindings;

public class XsuaaResourceServerJwkConfigurationTests {

    // create an ApplicationContextRunner that will create a context with the configuration under test.
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(OAuth2ResourceServerPropertiesExposing.class, 
                                                                                                                                  XsuaaResourceServerJwkConfiguration.class)); 
    @Autowired
    private ApplicationContext context;
    
    @Test
    public final void test_constructor() {
        new XsuaaResourceServerJwkConfiguration(new OAuth2ResourceServerProperties());
    }
    
    @Test
    public final void test_constructor_throwsIf_PropertiesAreNull() {
        assertThatThrownBy(() -> {
            new XsuaaResourceServerJwkConfiguration(null);
        }).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Properties must not be null");
    }

    @Test
    public final void test_jwtDecoderByJwkKeySetUri() {
        
        contextRunner.withPropertyValues("spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://authentication.sap.com/token_keys")
                      .run((context) -> {
                         assertThat(context.getBean("jwtDecoderByJwkKeySetUri")).isNotNull();
                         assertThat(context.getBean("jwtDecoderByJwkKeySetUri")).isInstanceOf(JwtDecoder.class);
                         assertThat(context.getBean(JwtDecoder.class)).isNotNull();
                      });
    }

    @Test
    public final void test_jwtDecoderByIssuerUri() {
//        fail("Not yet implemented");
    }

    @Test
    public final void test_xsuaaServiceBindings() {
//        fail("Not yet implemented");
    }

    @Test
    public final void test_xsuaaServiceBindingsFromFile() {
        
        contextRunner.run((context) -> {
                         assertThat(context.getBean("xsuaaServiceBindingsFromFile")).isNotNull();
                         assertThat(context.getBean("xsuaaServiceBindingsFromFile")).isInstanceOf(XsuaaServiceBindings.class);
                         assertThat(context.getBean(XsuaaServiceBindings.class)).isNotNull();
                      });
        
        contextRunner.withClassLoader(new FilteredClassLoader(new ClassPathResource("vcap-services.json")))
                     .withPropertyValues("VCAP_SERVICES={}") // make sure that environment is set, if no vcap file is present. Otherwise the alternative bean will fail during creation.
                     .run((context) -> {
                        assertThat(context).doesNotHaveBean("xsuaaServiceBindingsFromFile");
                      });
    }
    
    @Configuration
    public static class OAuth2ResourceServerPropertiesExposing {
        
        @Bean
        public OAuth2ResourceServerProperties properties() {
            return new OAuth2ResourceServerProperties();
        }
    }
}
