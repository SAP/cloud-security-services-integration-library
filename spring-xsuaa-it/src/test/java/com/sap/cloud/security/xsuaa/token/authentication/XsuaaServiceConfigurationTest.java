package com.sap.cloud.security.xsuaa.token.authentication;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { ConfigurationTestBean.class,XsuaaServiceConfigurationDefault.class })
public class XsuaaServiceConfigurationTest {

	@Autowired
	ConfigurationTestBean exampleBean;



	@Test
	public void testInjectedPropertyValue() {
		Assert.assertEquals("https://auth.com", exampleBean.xsuaaUrl);
		Assert.assertEquals("xs2.usertoken", exampleBean.xsuaaClientId);
		Assert.assertEquals("secret", exampleBean.xsuaaClientSecret);
		Assert.assertEquals("auth.com", exampleBean.xsuaaDomain);

		Assert.assertEquals("https://auth.com", exampleBean.serviceConfiguration.getUaaUrl());
		Assert.assertEquals("xs2.usertoken", exampleBean.serviceConfiguration.getClientId());
		Assert.assertEquals("secret", exampleBean.serviceConfiguration.getClientSecret());
		Assert.assertEquals("https://auth.com/token_keys", exampleBean.serviceConfiguration.getTokenKeyUrl("uaa", null));
		Assert.assertEquals("https://myhost.auth.com/token_keys", exampleBean.serviceConfiguration.getTokenKeyUrl("zone", "myhost"));
		Assert.assertEquals("java-hello-world", exampleBean.serviceConfiguration.getAppId());
		Assert.assertEquals("auth.com", exampleBean.serviceConfiguration.getUaaDomain());
	}

}

@Configuration
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "/vcap.json" })
class ConfigurationTestBean {

	@Autowired
	XsuaaServiceConfigurationDefault serviceConfiguration;

	@Value("${xsuaa.url:}")
	public String xsuaaUrl;

	@Value("${xsuaa.uaadomain:}")
	public String xsuaaDomain;

	@Value("${xsuaa.clientid:}")
	public String xsuaaClientId;

	@Value("${xsuaa.clientsecret:}")
	public String xsuaaClientSecret;


	@Value("${xsuaa.unknown:}")
	private String unknown;
}

@Configuration
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "/vcap.json" })
class UaaBindingData {

	@Autowired
	XsuaaServiceConfigurationDefault serviceConfiguration;

}