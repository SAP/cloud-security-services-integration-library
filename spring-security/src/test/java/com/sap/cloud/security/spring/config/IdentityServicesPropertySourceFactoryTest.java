/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(classes = { TestConfigurationFromFile.class })
class IdentityServicesPropertySourceFactoryTest {

	@Autowired
	TestConfigurationFromFile configuration;

	@Test
	void testInjectedPropertyValues() {
		assertEquals("client-id", configuration.xsuaaClientId);
		assertEquals("client-secret", configuration.xsuaaClientSecret);
		assertEquals("http://domain.xsuaadomain", configuration.xsuaaUrl);
		assertEquals("xsuaadomain", configuration.xsuaaDomain);
		assertEquals("xsappname", configuration.xsuaaAppName);
		assertEquals("xsuaaInstance0", configuration.xsuaaName);
		assertEquals("application", configuration.xsuaaPlan.toLowerCase());

		assertEquals("", configuration.unknown);

		assertEquals("client-id-ias", configuration.identityClientId);
		assertEquals("client-secret-ias", configuration.identityClientSecret);
		assertEquals("iasdomain", configuration.identityDomains.get(0));
		assertEquals("identityInstance0", configuration.identityName);
		assertEquals("broker", configuration.identityPlan.toLowerCase());
	}
}

@Configuration
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, value = {
		"classpath:singleXsuaaAndIasBinding.json" })
class TestConfigurationFromFile {

	@Value("${sap.security.services.xsuaa.url:}")
	public String xsuaaUrl;

	@Value("${sap.security.services.xsuaa.uaadomain:}")
	public String xsuaaDomain;

	@Value("${sap.security.services.xsuaa.clientid:}")
	public String xsuaaClientId;

	@Value("${sap.security.services.xsuaa.clientsecret:}")
	public String xsuaaClientSecret;

	@Value("${sap.security.services.xsuaa.xsappname:}")
	public String xsuaaAppName;

	@Value("${sap.security.services.xsuaa.name:}")
	public String xsuaaName;

	@Value("${sap.security.services.xsuaa.plan:}")
	public String xsuaaPlan;

	@Value("${sap.security.services.xsuaa.unknown:}")
	public String unknown;

	@Value("${sap.security.services.identity.clientid:}")
	public String identityClientId;

	@Value("${sap.security.services.identity.clientsecret:}")
	public String identityClientSecret;

	@Value("${sap.security.services.identity.domains:}")
	public List<String> identityDomains;

	@Value("${sap.security.services.identity.name:}")
	public String identityName;

	@Value("${sap.security.services.identity.plan:}")
	public String identityPlan;
}
