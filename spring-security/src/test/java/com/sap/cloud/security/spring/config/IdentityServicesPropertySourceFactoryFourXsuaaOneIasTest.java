/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.List;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.ServiceBindingEnvironment;
import com.sap.cloud.security.config.ServiceConstants;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

/**
 * Tests that the {@link IdentityServicesPropertySourceFactory} puts 2 XSUAA service instances with plan 'application' and 2 with plan 'broker' into the Spring properties
 * in the correct order.
 * For backward-compatibility, the order of the service instance must be as follows:
 * Index 0: Configuration accessible via Environment#getXsuaaConfiguration (Application)
 * Index 1: Configuration accessible via Environment#getXsuaaConfigurationForTokenExchange (Broker) if exists, otherwise next XSUAA configuration
 * Index 2+: Remaining XSUAA configurations
 * In addition, tests that the IAS service instance from the environment is correctly added as well.
 */
@SpringBootTest(classes = { FourXsuaaOneIasTestConfigurationFromFile.class })
class IdentityServicesPropertySourceFactoryFourXsuaaOneIasTest {

	@Autowired
	FourXsuaaOneIasTestConfigurationFromFile configuration;

	static String serviceBindingJson;

	@BeforeAll
	static void setup() throws IOException {
		serviceBindingJson = IOUtils.resourceToString("/fourXsuaaBindingsAndOneIasBinding.json", UTF_8);
	}

	@Test
	void testInjectedPropertyValues() {
		ServiceBindingEnvironment env = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> serviceBindingJson));

		/* Index 0 */
		OAuth2ServiceConfiguration xsuaaConfig = env.getXsuaaConfiguration();
		assertEquals(xsuaaConfig.getClientId(), configuration.xsuaaClientId0);
		assertEquals(xsuaaConfig.getClientSecret(), configuration.xsuaaClientSecret0);
		assertEquals(xsuaaConfig.getProperty(ServiceConstants.URL), configuration.xsuaaUrl0);
		assertEquals(xsuaaConfig.getProperty(ServiceConstants.XSUAA.UAA_DOMAIN), configuration.xsuaaDomain0);
		assertEquals(xsuaaConfig.getProperty(ServiceConstants.XSUAA.APP_ID), configuration.xsuaaAppName0);
		assertEquals(ServiceConstants.Plan.APPLICATION, ServiceConstants.Plan.from(configuration.xsuaaPlan0));
		assertEquals("", configuration.unknown0);

		/* Index 1 */
		OAuth2ServiceConfiguration xsuaaTokenExchangeConfig = env.getXsuaaConfigurationForTokenExchange();
		assertEquals(xsuaaTokenExchangeConfig.getClientId(), configuration.xsuaaClientId1);
		assertEquals(xsuaaTokenExchangeConfig.getClientSecret(), configuration.xsuaaClientSecret1);
		assertEquals(ServiceConstants.Plan.BROKER, ServiceConstants.Plan.from(configuration.xsuaaPlan1));

		/* Index 2 */
		assertEquals("client-id-broker2", configuration.xsuaaClientId2);
		assertEquals("client-secret-broker2", configuration.xsuaaClientSecret2);
		assertEquals(ServiceConstants.Plan.BROKER, ServiceConstants.Plan.from(configuration.xsuaaPlan2));

		/* Index 3 */
		assertEquals("client-id", configuration.xsuaaClientId3);
		assertEquals("client-secret", configuration.xsuaaClientSecret3);
		assertEquals("xsappname", configuration.xsuaaAppName3);
		assertEquals(ServiceConstants.Plan.APPLICATION, ServiceConstants.Plan.from(configuration.xsuaaPlan3));
		
		/* IAS */
		assertEquals("client-id-ias", configuration.identityClientId);
		assertEquals("client-secret-ias", configuration.identityClientSecret);
		assertTrue(configuration.identityDomains.contains("iasdomain"));
		assertTrue(configuration.identityDomains.contains("iasdomain.com"));
		assertEquals(2, configuration.identityDomains.size());
		assertEquals(ServiceConstants.Plan.BROKER, ServiceConstants.Plan.from(configuration.iasPlan));
	}
}

@Configuration
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, value = {
		"classpath:fourXsuaaBindingsAndOneIasBinding.json" })
class FourXsuaaOneIasTestConfigurationFromFile {

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

	@Value("${sap.security.services.xsuaa[0].plan:}")
	public String xsuaaPlan0;

	@Value("${sap.security.services.xsuaa[0].unknown:}")
	public String unknown0;
	
	/* Index 1 */
	
	@Value("${sap.security.services.xsuaa[1].clientid:}")
	public String xsuaaClientId1;

	@Value("${sap.security.services.xsuaa[1].clientsecret:}")
	public String xsuaaClientSecret1;

	@Value("${sap.security.services.xsuaa[1].plan:}")
	public String xsuaaPlan1;

	
	/* Index 2 */
	
	@Value("${sap.security.services.xsuaa[2].clientid:}")
	public String xsuaaClientId2;

	@Value("${sap.security.services.xsuaa[2].clientsecret:}")
	public String xsuaaClientSecret2;

	@Value("${sap.security.services.xsuaa[2].plan:}")
	public String xsuaaPlan2;

	/* Index 3 */
	
	@Value("${sap.security.services.xsuaa[3].clientid:}")
	public String xsuaaClientId3;

	@Value("${sap.security.services.xsuaa[3].clientsecret:}")
	public String xsuaaClientSecret3;

	@Value("${sap.security.services.xsuaa[3].xsappname:}")
	public String xsuaaAppName3;

	@Value("${sap.security.services.xsuaa[3].plan:}")
	public String xsuaaPlan3;
	
	/* IAS */
	
	@Value("${sap.security.services.identity.clientid:}")
	public String identityClientId;

	@Value("${sap.security.services.identity.clientsecret:}")
	public String identityClientSecret;

	@Value("${sap.security.services.identity.domains:}")
	public List<String> identityDomains;

	@Value("${sap.security.services.identity.plan:}")
	public String iasPlan;
}
