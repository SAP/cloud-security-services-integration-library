/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import com.sap.cloud.security.config.ServiceBindingEnvironment;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Tests the integration between XsuaaServiceConfiguration and
 * IdentityServicesPropertySourceFactory. The XSUAA configuration properties of
 * the XsuaaServiceConfiguration are asserted to be equal to those of the
 * configuration used to populate the Spring properties via
 * IdentityServicesPropertySourceFactory.
 */
@SpringBootTest(classes = { SingleXsuaaConfigurationFromFile.class })
class XsuaaServiceConfigurationLoadingIntegrationTest {

	static ServiceBindingEnvironment env;

	@Autowired
	XsuaaServiceConfiguration xsuaaConfig;

	@BeforeAll
	static void setup() throws IOException {
		String serviceBindingJson = IOUtils.resourceToString("/singleXsuaaAndIasBinding.json", UTF_8);
		env = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> serviceBindingJson));
	}

	@Test
	void configuresXsuaaServiceConfiguration() {
		ConfigurationAssertions.assertXsuaaConfigsAreEqual(xsuaaConfig, env.getXsuaaConfiguration());
	}

}

@Configuration
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, value = {
		"classpath:singleXsuaaAndIasBinding.json" })
@EnableConfigurationProperties(XsuaaServiceConfiguration.class)
class SingleXsuaaConfigurationFromFile {
}
