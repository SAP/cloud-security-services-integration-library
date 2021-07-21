/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.util.Properties;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { CustomConfiguration.class })
@EnableConfigurationProperties(value = XsuaaServiceConfigurationDefault.class)
public class CustomPropertySourceFactoryTest {

	@Autowired
	CustomConfiguration customConfiguration;

	@Autowired
	XsuaaServiceConfigurationDefault serviceConfiguration;

	@Test
	public void testXsuaaServiceConfiguration() {
		Assert.assertEquals("https://auth.com", serviceConfiguration.getUaaUrl()); // vcap.json
		Assert.assertEquals("overwriteUaaDomain", serviceConfiguration.getUaaDomain()); // vcap.json
	}

	@Test
	public void testOverwrittenXsuaaServiceConfiguration() {
		Assert.assertEquals("customClientId", serviceConfiguration.getClientId());
		Assert.assertEquals("customClientSecret", serviceConfiguration.getClientSecret());
		Assert.assertEquals("customAppId!t2344", serviceConfiguration.getAppId());
	}

	@Test
	public void testInjectedPropertyValue() {
		Assert.assertEquals("https://auth.com", customConfiguration.xsuaaUrl); // vcap.json
		Assert.assertEquals("overwriteUaaDomain", customConfiguration.xsuaaDomain); // vcap.json
	}

	@Test
	public void testOverwrittenInjectedPropertyValue() {
		Assert.assertEquals("customClientId", customConfiguration.xsuaaClientId);
		Assert.assertEquals("customClientSecret", customConfiguration.xsuaaClientSecret);
		Assert.assertEquals("customAppId!t2344", customConfiguration.xsappId);
	}
}

@Configuration
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = "classpath:/vcap.json")
@PropertySource(factory = CustomPropertySourceFactory.class, value = "")
class CustomConfiguration {

	@Value("${xsuaa.url:}")
	public String xsuaaUrl;

	@Value("${xsuaa.uaadomain:}")
	public String xsuaaDomain;

	@Value("${xsuaa.clientid:}")
	public String xsuaaClientId;

	@Value("${xsuaa.clientsecret:}")
	public String xsuaaClientSecret;

	@Value("${xsuaa.xsappname:}")
	public String xsappId;
}

class CustomPropertySourceFactory implements PropertySourceFactory {
	private final String vcapJsonString = "{\"xsuaa\":[{\"credentials\":{\"xsappname\":\"customAppId!t2344\"},\"plan\": \"application\",\"tags\":[\"xsuaa\"]}]}";

	@Override
	public org.springframework.core.env.PropertySource<?> createPropertySource(String s,
			EncodedResource encodedResource) throws IOException {

		Properties properties = new XsuaaServicesParser(vcapJsonString).parseCredentials();

		properties.put("clientid", "customClientId");
		properties.put("clientsecret", "customClientSecret");
		properties.put("uaadomain", "overwriteUaaDomain");

		return XsuaaServicePropertySourceFactory.create("custom", properties);
	}
}