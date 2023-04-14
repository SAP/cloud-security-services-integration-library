/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Properties;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.Environments;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { CustomConfiguration.class, XsuaaServiceConfigurationDefault.class })
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
			EncodedResource encodedResource) {

		Properties properties = new Properties();
		Environment environment = Environments
				.readFromInput(new ByteArrayInputStream(vcapJsonString.getBytes(StandardCharsets.UTF_8)));
		for (Map.Entry<String, String> property : environment.getXsuaaConfiguration().getProperties().entrySet()) {
			properties.put(property.getKey(), property.getValue());
		}

		properties.put("clientid", "customClientId");
		properties.put("clientsecret", "customClientSecret");
		properties.put("uaadomain", "overwriteUaaDomain");

		return XsuaaServicePropertySourceFactory.create("custom", properties);
	}
}