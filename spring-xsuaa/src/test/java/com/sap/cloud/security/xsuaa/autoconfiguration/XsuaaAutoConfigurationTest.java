package com.sap.cloud.security.xsuaa.autoconfiguration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.token.flows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.VariableKeySetUriTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlows;

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

@RunWith(SpringRunner.class)
@SpringBootTest(classes = XsuaaAutoConfiguration.class)
public class XsuaaAutoConfigurationTest {

	// create an ApplicationContextRunner that will create a context with the
	// configuration under test.
	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(XsuaaAutoConfiguration.class));

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
        assertThat(context.getBean("xsuaaTokenDecoder")).isInstanceOf(VariableKeySetUriTokenDecoder.class);
        assertThat(context.getBean(VariableKeySetUriTokenDecoder.class)).isNotNull(); 
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
            assertThat(context).hasSingleBean(VariableKeySetUriTokenDecoder.class);
            assertThat(context).hasSingleBean(RestTemplate.class);
            
            UserConfiguration customConfig = context.getBean(UserConfiguration.class);
            XsuaaTokenFlows expectedCustomTokenFlows = customConfig.userDefinedXsuaaTokenFlows(customConfig.userDefinedXsuaaTokenFlowRestTemplate(), customConfig.userDefinedXsuaaTokenDecoder());
            VariableKeySetUriTokenDecoder expectedCustomTokenDecoder = customConfig.userDefinedXsuaaTokenDecoder();
            RestTemplate expectedCustomRestTemplate = customConfig.userDefinedXsuaaTokenFlowRestTemplate();
            
            assertThat(context.getBean(XsuaaTokenFlows.class)).isSameAs(expectedCustomTokenFlows);
            assertThat(context.getBean(VariableKeySetUriTokenDecoder.class)).isSameAs(expectedCustomTokenDecoder);
            assertThat(context.getBean(RestTemplate.class)).isSameAs(expectedCustomRestTemplate);
        });
    }

	@Test
	public final void autoConfigurationActive() {
		contextRunner.run((context) -> {
			assertThat(context.containsBean("xsuaaServiceConfiguration"), is(true));
			assertThat(context.getBean("xsuaaServiceConfiguration"),
					instanceOf(XsuaaServiceConfigurationDefault.class));
			assertThat(context.getBean(XsuaaServiceConfiguration.class), is(not(nullValue())));
		});
	}

	@Test
	public final void autoConfigurationActiveInclProperties() {
		contextRunner
				.withPropertyValues("spring.xsuaa.auto:true")
				.withPropertyValues("spring.xsuaa.multiple-bindings:false").run((context) -> {
					assertThat(context.containsBean("xsuaaServiceConfiguration"), is(true));
					assertThat(context.getBean("xsuaaServiceConfiguration"),
							instanceOf(XsuaaServiceConfigurationDefault.class));
					assertThat(context.getBean(XsuaaServiceConfiguration.class), is(not(nullValue())));
				});
	}

	@Test
	public void autoConfigurationDisabledByProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.auto:false").run((context) -> {
			assertThat(context.containsBean("xsuaaServiceConfiguration"), is(false));
		});
	}

	@Test
	public void serviceConfigurationDisabledByProperty() {
		contextRunner.withPropertyValues("spring.xsuaa.multiple-bindings:true").run((context) -> {
			assertThat(context.containsBean("xsuaaServiceConfiguration"), is(false));
		});
	}

	@Test
	public final void autoConfigurationWithoutJwtOnClasspathInactive() {
		contextRunner.withClassLoader(new FilteredClassLoader(Jwt.class)) // removes Jwt.class from classpath
				.run((context) -> {
					assertThat(context.containsBean("xsuaaServiceConfiguration"), is(false));
				});
	}

	@Test
	public final void userConfigurationCanOverrideDefaultBeans() {
		contextRunner.withUserConfiguration(UserConfiguration.class)
				.run((context) -> {
					assertThat(context.containsBean("xsuaaServiceConfiguration"), is(false));
					assertThat(context.containsBean("customServiceConfiguration"), is(true));
					assertThat(context.getBean("customServiceConfiguration"),
							instanceOf(CustomXsuaaConfiguration.class));
				});
	}

	@Configuration
	public static class UserConfiguration {

		@Bean
		public XsuaaServiceConfiguration customServiceConfiguration() {
			return new CustomXsuaaConfiguration();
		}
		
		@Bean
        public XsuaaTokenFlows userDefinedXsuaaTokenFlows(RestTemplate restTemplate, VariableKeySetUriTokenDecoder decoder) {
            return new XsuaaTokenFlows(restTemplate, decoder);
        }
        
        @Bean
        public VariableKeySetUriTokenDecoder userDefinedXsuaaTokenDecoder() {
            return new NimbusTokenDecoder();
        }
        
        @Bean
        public RestTemplate userDefinedXsuaaTokenFlowRestTemplate() {
            return new RestTemplate();
        }
	}

	static class CustomXsuaaConfiguration implements XsuaaServiceConfiguration {

		@Override
		public String getClientId() {
			return null;
		}

		@Override
		public String getClientSecret() {
			return null;
		}

		@Override
		public String getUaaUrl() {
			return null;
		}

		@Override
		public String getTokenKeyUrl(String zid, String subdomain) {
			return null;
		}

		@Override
		public String getAppId() {
			return null;
		}

		@Override
		public String getUaaDomain() {
			return null;
		}
	}
}
