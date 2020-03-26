package com.sap.cloud.security.xsuaa;

import static org.hamcrest.CoreMatchers.startsWith;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { TestConfiguration.class, XsuaaServiceConfigurationDefault.class })
public class XsuaaServicePropertySourceFactoryTest {

	@Autowired
	TestConfiguration testConfiguration;

	@Autowired
	XsuaaServiceConfigurationDefault serviceConfiguration;

	@Test
	public void testXsuaaServiceConfiguration() {
		Assert.assertEquals("xs2.usertoken", serviceConfiguration.getClientId());
		Assert.assertEquals("secret", serviceConfiguration.getClientSecret());
		Assert.assertEquals("https://auth.com", serviceConfiguration.getUaaUrl());
		Assert.assertEquals("auth.com", serviceConfiguration.getUaaDomain());
		Assert.assertThat(testConfiguration.certificate, startsWith("-----BEGIN CERTIFICATE-----"));
		Assert.assertThat(testConfiguration.key, startsWith("-----BEGIN RSA PRIVATE KEY-----"));
	}

	@Test
	public void testInjectedPropertyValue() {
		Assert.assertEquals("xs2.usertoken", testConfiguration.xsuaaClientId);
		Assert.assertEquals("secret", testConfiguration.xsuaaClientSecret);
		Assert.assertEquals("https://auth.com", testConfiguration.xsuaaUrl);
		Assert.assertEquals("auth.com", testConfiguration.xsuaaDomain);
		Assert.assertEquals("", testConfiguration.unknown);
		Assert.assertThat(testConfiguration.certificate, startsWith("-----BEGIN CERTIFICATE-----"));
		Assert.assertThat(testConfiguration.key, startsWith("-----BEGIN RSA PRIVATE KEY-----"));
	}

}

@Configuration
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "/vcap.json" })
class TestConfiguration {

	@Value("${xsuaa.url:}")
	public String xsuaaUrl;

	@Value("${xsuaa.uaadomain:}")
	public String xsuaaDomain;

	@Value("${xsuaa.clientid:}")
	public String xsuaaClientId;

	@Value("${xsuaa.clientsecret:}")
	public String xsuaaClientSecret;

	@Value("${xsuaa.unknown:}")
	public String unknown;

	@Value("${xsuaa.certificate:}")
	public String certificate;

	@Value("${xsuaa.key:}")
	public String key;
}