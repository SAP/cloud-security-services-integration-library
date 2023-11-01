/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@SpringBootTest(classes = { BrokerHoleTestConfigurationFromFile.class })
class IdentityServicesPropertySourceFactoryBrokerNoHoleTest {

	@Autowired
	BrokerHoleTestConfigurationFromFile configuration;

	@Test
	void testInjectedPropertyValues_fourXsuaaBindings() {
		/* Index 0 */
		assertEquals("client-id2", configuration.xsuaaClientId0);
		assertEquals("client-secret2", configuration.xsuaaClientSecret0);
		assertEquals("http://domain.xsuaadomain", configuration.xsuaaUrl0);
		assertEquals("xsuaadomain", configuration.xsuaaDomain0);
		assertEquals("xsappname2", configuration.xsuaaAppName0);
		assertEquals("", configuration.unknown0);

		/* Index 1 */
		assertEquals("client-id", configuration.xsuaaClientId1);
		assertEquals("client-secret", configuration.xsuaaClientSecret1);
		assertEquals("xsappname", configuration.xsuaaAppName1);

		/* Index 2 */
		assertEquals("none", configuration.xsuaaClientId2);
		assertEquals("none", configuration.xsuaaClientSecret2);
		
		/* IAS */
		assertEquals("client-id-ias", configuration.identityClientId);
		assertEquals("client-secret-ias", configuration.identityClientSecret);
		assertTrue(configuration.identityDomains.contains("iasdomain"));
		assertTrue(configuration.identityDomains.contains("iasdomain.com"));
		assertEquals(2, configuration.identityDomains.size());
	}
}

@Configuration
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, value = {
		"classpath:xsuaaBindingsWithHole.json" })
class BrokerHoleTestConfigurationFromFile {

	/* Index 0 */
	
	@Value("${sap.security.services.xsuaa[0].url:}")
	public String xsuaaUrl0;

	@Value("${sap.security.services.xsuaa[0].uaadomain:}")
	public String xsuaaDomain0;

	@Value("${sap.security.services.xsuaa[0].clientid:}")
	public String xsuaaClientId0;

	@Value("${sap.security.services.xsuaa[0].clientsecret:}")
	public String xsuaaClientSecret0;

	@Value("${sap.security.services.xsuaa[0].xsappname:}")
	public String xsuaaAppName0;

	@Value("${sap.security.services.xsuaa[0].unknown:}")
	public String unknown0;

	
	/* Index 1 */
	
	@Value("${sap.security.services.xsuaa[1].clientid:none}")
	public String xsuaaClientId1;

	@Value("${sap.security.services.xsuaa[1].clientsecret:none}")
	public String xsuaaClientSecret1;

	@Value("${sap.security.services.xsuaa[1].xsappname}")
	public String xsuaaAppName1;
	
	/* Index 2 */
	
	@Value("${sap.security.services.xsuaa[2].clientid:none}")
	public String xsuaaClientId2;

	@Value("${sap.security.services.xsuaa[2].clientsecret:none}")
	public String xsuaaClientSecret2;
	

	
	/* IAS */
	
	@Value("${sap.security.services.identity.clientid:}")
	public String identityClientId;

	@Value("${sap.security.services.identity.clientsecret:}")
	public String identityClientSecret;

	@Value("${sap.security.services.identity.domains:}")
	public List<String> identityDomains;
}
