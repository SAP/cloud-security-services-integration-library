package com.sap.cloud.security.xsuaa.autoconfiguration;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.tokenflows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.tokenflows.TokenDecoder;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = XsuaaDefaultConfigurations.class)
public class XsuaaDefaultConfigurationsTests {

    // create an ApplicationContextRunner that will create a context with the configuration under test.
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(XsuaaDefaultConfigurations.class));
    
    @Autowired
    private ApplicationContext context;

    @Test
    public final void test_xsuaaTokenFlows() {
        assertThat(context.getBean("xsuaaTokenFlows")).isNotNull();
        assertThat(context.getBean("xsuaaTokenFlows")).isInstanceOf(XsuaaTokenFlows.class);
        assertThat(context.getBean(XsuaaTokenFlows.class)).isNotNull();
    }
    
    @Test
    public final void test_xsuaaTokenDecoder() {
        assertThat(context.getBean("xsuaaTokenDecoder")).isNotNull();
        assertThat(context.getBean("xsuaaTokenDecoder")).isInstanceOf(TokenDecoder.class);
        assertThat(context.getBean(TokenDecoder.class)).isNotNull(); 
    }

    @Test
    public final void test_xsuaaTokenFlowRestTemplate() {
        assertThat(context.getBean("xsuaaTokenFlowRestTemplate")).isNotNull();
        assertThat(context.getBean("xsuaaTokenFlowRestTemplate")).isInstanceOf(RestTemplate.class);
        assertThat(context.getBean(RestTemplate.class)).isNotNull();       
    }

    @Test
    public final void test_configurationIsInactive_if_noJwtOnClasspath() {
        
        // check that the beans are there, if Jwt.class is on the classpath.
        // Note: this is a safety check, to make sure that the test below succeeds really
        //       as a result of Jwt.class being missing from the classpath.
        contextRunner.run((context) -> {
                         assertThat(context).hasBean("xsuaaTokenFlows");
                         assertThat(context).hasBean("xsuaaTokenDecoder");
                         assertThat(context).hasBean("xsuaaTokenFlowRestTemplate");
                      });
        
        // check that the beans are NOT there, if Jwt.class is filtered out of the classpath.
        contextRunner.withClassLoader(new FilteredClassLoader(Jwt.class)) // make sure Jwt.class is not on the classpath.
                     .run((context) -> {
                        assertThat(context).doesNotHaveBean("xsuaaTokenFlows");
                        assertThat(context).doesNotHaveBean("xsuaaTokenDecoder");
                        assertThat(context).doesNotHaveBean("xsuaaTokenFlowRestTemplate");
                      });
    }
        
    @Test
    public final void test_userConfigurationsCanOverrideDefaultBeans() { 
        contextRunner.withUserConfiguration(UserConfiguration.class)
        .run((context) -> {
            assertThat(context).hasSingleBean(XsuaaTokenFlows.class);
            assertThat(context).hasSingleBean(TokenDecoder.class);
            assertThat(context).hasSingleBean(RestTemplate.class);
            
            UserConfiguration customConfig = context.getBean(UserConfiguration.class);
            XsuaaTokenFlows expectedCustomTokenFlows = customConfig.userDefinedXsuaaTokenFlows(customConfig.userDefinedXsuaaTokenFlowRestTemplate(), customConfig.userDefinedXsuaaTokenDecoder());
            TokenDecoder expectedCustomTokenDecoder = customConfig.userDefinedXsuaaTokenDecoder();
            RestTemplate expectedCustomRestTemplate = customConfig.userDefinedXsuaaTokenFlowRestTemplate();
            
            assertThat(context.getBean(XsuaaTokenFlows.class)).isSameAs(expectedCustomTokenFlows);
            assertThat(context.getBean(TokenDecoder.class)).isSameAs(expectedCustomTokenDecoder);
            assertThat(context.getBean(RestTemplate.class)).isSameAs(expectedCustomRestTemplate);
        });
    }
    
    @Configuration
    public static class UserConfiguration {
        
        @Bean
        public XsuaaTokenFlows userDefinedXsuaaTokenFlows(RestTemplate restTemplate, TokenDecoder decoder) {
            return new XsuaaTokenFlows(restTemplate, decoder);
        }
        
        @Bean
        public TokenDecoder userDefinedXsuaaTokenDecoder() {
            return new NimbusTokenDecoder();
        }
        
        @Bean
        public RestTemplate userDefinedXsuaaTokenFlowRestTemplate() {
            return new RestTemplate();
        }
    }
}
