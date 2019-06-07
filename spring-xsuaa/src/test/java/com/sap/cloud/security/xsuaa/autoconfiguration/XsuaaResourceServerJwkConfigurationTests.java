package com.sap.cloud.security.xsuaa.autoconfiguration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;

import org.junit.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnResource;
import org.springframework.boot.autoconfigure.security.oauth2.resource.IssuerUriCondition;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;

import com.sap.cloud.security.xsuaa.DefaultXsuaaServiceBindings;
import com.sap.cloud.security.xsuaa.XsuaaServiceBindings;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaResourceServerJwkConfiguration.MissingVcapServicesFileCondition;

public class XsuaaResourceServerJwkConfigurationTests {

    // create an ApplicationContextRunner that will create a context with the configuration under test.
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(OAuth2ResourceServerPropertiesExposing.class, 
                                                                                                                                  XsuaaResourceServerJwkConfiguration.class));
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
        
        // positive test: jwk-set-uri is set. Should provide a bean.
        contextRunner.withPropertyValues("spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://authentication.sap.com/token_keys")
                      .run((context) -> {
                         assertThat(context.getBean("jwtDecoderByJwkKeySetUri")).isNotNull();
                         assertThat(context.getBean("jwtDecoderByJwkKeySetUri")).isInstanceOf(JwtDecoder.class);
                         assertThat(context.getBean(JwtDecoder.class)).isNotNull();
                      });
        
        // negative test: jwk-set-uri is NOT set. Should NOT provide a bean.
        contextRunner.run((context) -> {
           assertThat(context).doesNotHaveBean("jwtDecoderByJwkKeySetUri");
        });
    }
    
    @Test
    public final void test_jwtDecoderByIssuerUri() {
        
        ApplicationContextRunner contextRunner = new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(OAuth2ResourceServerPropertiesExposing.class, 
                                                                                                                        XsuaaResourceServerJwkConfigurationSubclass.class));
        // positive test: jwk-set-uri is set. Should provide a bean.
        contextRunner.withPropertyValues("spring.security.oauth2.resourceserver.jwt.issuer-uri=https://authentication.eu10.hana.ondemand.com")
                      .run((context) -> {
                         assertThat(context).hasBean("jwtDecoderByIssuerUri");
                         assertThat(context.getBean("jwtDecoderByIssuerUri")).isInstanceOf(JwtDecoder.class);
                         assertThat(context.getBean(JwtDecoder.class)).isNotNull();
                      });
        
        // negative test: jwk-set-uri is NOT set. Should NOT provide a bean.
        contextRunner.run((context) -> {
           assertThat(context).doesNotHaveBean("jwtDecoderByIssuerUri");
        });
    }

    @Test
    public final void test_xsuaaServiceBindings() {
        
        // positive test: if no vcap-services.json is found, a bean should be exposed that reads from the environment.
        contextRunner.withPropertyValues("VCAP_SERVICES={}")
                     .withClassLoader(new FilteredClassLoader(new ClassPathResource("vcap-services.json")))
                     .run((context) -> {
                         assertThat(context).hasBean("xsuaaServiceBindings");
                         assertThat(context.getBean("xsuaaServiceBindings")).isInstanceOf(XsuaaServiceBindings.class);
                         assertThat(context.getBean(XsuaaServiceBindings.class)).isNotNull();
                      });
        
        // negative test: if vcap-services.json IS found, a bean should NOT be exposed.
        contextRunner.run((context) -> {
                         assertThat(context).doesNotHaveBean("xsuaaServiceBindings");
                      });
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
    
    @Test
    public final void test_userConfigurationsCanOverrideDefaultBeans() {
        
        // test with jwkSetUri set and VCAPs from file.
        contextRunner.withUserConfiguration(UserConfiguration.class)
                     .withPropertyValues("spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://authentication.sap.com/token_keys")
                     .run((context) -> {
                         assertThat(context).hasSingleBean(JwtDecoder.class);
                         assertThat(context).hasSingleBean(XsuaaServiceBindings.class);
                         
                         UserConfiguration customConfig = context.getBean(UserConfiguration.class);
                         OAuth2ResourceServerPropertiesExposing oauth2PropertiesConfig = context.getBean(OAuth2ResourceServerPropertiesExposing.class);
                         
                         JwtDecoder expectedJwtDecoder = customConfig.jwtDecoderByJwkKeySetUri(customConfig.xsuaaServiceBindingsFromFile(), oauth2PropertiesConfig.properties());
                         XsuaaServiceBindings expectedXsuaaServiceBindings = customConfig.xsuaaServiceBindingsFromFile();
                         
                         assertThat(context.getBean(JwtDecoder.class)).isSameAs(expectedJwtDecoder);
                         assertThat(context.getBean(XsuaaServiceBindings.class)).isSameAs(expectedXsuaaServiceBindings);
                      });
        
        // test with issuerURI set and VCAPs from environment.
        contextRunner.withUserConfiguration(UserConfiguration.class)
                     .withPropertyValues("spring.security.oauth2.resourceserver.jwt.issuer-uri=https://authentication.eu10.hana.ondemand.com", "VCAP_SERVICES={}")
                     .withClassLoader(new FilteredClassLoader(new ClassPathResource("vcap-services.json")))    
                     .run((context) -> {
                         assertThat(context).hasSingleBean(JwtDecoder.class);
                         assertThat(context).hasSingleBean(XsuaaServiceBindings.class);
                        
                         UserConfiguration customConfig = context.getBean(UserConfiguration.class);
                         OAuth2ResourceServerPropertiesExposing oauth2PropertiesConfig = context.getBean(OAuth2ResourceServerPropertiesExposing.class);
                        
                         JwtDecoder expectedJwtDecoder = customConfig.jwtDecoderByIssuerUri(customConfig.xsuaaServiceBindings(), oauth2PropertiesConfig.properties());
                         XsuaaServiceBindings expectedXsuaaServiceBindings = customConfig.xsuaaServiceBindings();
                        
                         assertThat(context.getBean(JwtDecoder.class)).isSameAs(expectedJwtDecoder);
                         assertThat(context.getBean(XsuaaServiceBindings.class)).isSameAs(expectedXsuaaServiceBindings);
                      });
    }
    
    @Configuration
    public static class OAuth2ResourceServerPropertiesExposing {
        
        @Bean
        public OAuth2ResourceServerProperties properties() {
            OAuth2ResourceServerProperties properties = new OAuth2ResourceServerProperties();
            properties.getJwt().setJwkSetUri("http://authentication.sap.com/token_keys");
            properties.getJwt().setIssuerUri("https://authentication.eu10.hana.ondemand.com");
            return properties;
        }   
    }
    
    @Configuration
    public static class UserConfiguration {
        
        @Bean
        @ConditionalOnProperty(name = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri")
        public JwtDecoder jwtDecoderByJwkKeySetUri(XsuaaServiceBindings xsuaaServiceBindings, OAuth2ResourceServerProperties properties) {
            String jwkSetUri = properties.getJwt().getJwkSetUri();
            NimbusJwtDecoderJwkSupport jwtDecoder = new NimbusJwtDecoderJwkSupport(jwkSetUri);
            return jwtDecoder;
        }

        @Bean
        @Conditional(IssuerUriCondition.class)
        public JwtDecoder jwtDecoderByIssuerUri(XsuaaServiceBindings xsuaaServiceBindings, OAuth2ResourceServerProperties properties) {
            String jwkSetUri = properties.getJwt().getJwkSetUri();
            NimbusJwtDecoderJwkSupport jwtDecoder = new NimbusJwtDecoderJwkSupport(jwkSetUri);
            return jwtDecoder;
        }
        
        @Bean
        @Conditional(MissingVcapServicesFileCondition.class)
        public XsuaaServiceBindings xsuaaServiceBindings() {
            MockEnvironment environment = new MockEnvironment();
            environment.setProperty("VCAP_SERVICES", "{}");
            return new DefaultXsuaaServiceBindings(environment);
        }
        
        @Bean
        @ConditionalOnResource(resources = {"vcap-services.json"})
        public XsuaaServiceBindings xsuaaServiceBindingsFromFile() throws IOException {
            File vcapFile = new ClassPathResource("vcap-services.json").getFile();
            return new DefaultXsuaaServiceBindings(vcapFile);
        }
    }
}
