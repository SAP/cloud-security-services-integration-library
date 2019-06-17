package com.sap.cloud.security.xsuaa.autoconfiguration;

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
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

@RunWith(SpringRunner.class)
@SpringBootTest(classes = XsuaaAutoConfiguration.class)
public class XsuaaAutoConfigurationTest {

    // create an ApplicationContextRunner that will create a context with the configuration under test.
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(XsuaaAutoConfiguration.class));

    @Autowired
    private ApplicationContext context;

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
    }

    static class CustomXsuaaConfiguration implements XsuaaServiceConfiguration {

        @Override public String getClientId() {
            return null;
        }

        @Override public String getClientSecret() {
            return null;
        }

        @Override public String getUaaUrl() {
            return null;
        }

        @Override public String getTokenKeyUrl(String zid, String subdomain) {
            return null;
        }

        @Override public String getAppId() {
            return null;
        }

        @Override public String getUaaDomain() {
            return null;
        }
    }
}
