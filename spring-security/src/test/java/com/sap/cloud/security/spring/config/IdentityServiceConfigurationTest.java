/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.config.CredentialType;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.*;

class IdentityServiceConfigurationTest {

	private final ApplicationContextRunner runner = new ApplicationContextRunner();

	@EnableConfigurationProperties(IdentityServiceConfiguration.class)
	static class EnablePropertiesConfiguration {
	}

	@Test
	void configuresIdentityServiceConfiguration() {
		runner.withUserConfiguration(EnablePropertiesConfiguration.class)
				.withPropertyValues("sap.security.services.identity.url:http://localhost",
						"sap.security.services.identity.clientid:cid")
				.run(context -> {
					assertEquals("http://localhost",
							context.getBean(IdentityServiceConfiguration.class).getUrl().toString());
					assertNull(context.getBean(IdentityServiceConfiguration.class).getCredentialType());
					assertFalse(context.getBean(IdentityServiceConfiguration.class).getClientIdentity()
							.isCertificateBased());
					assertEquals("cid",
							context.getBean(IdentityServiceConfiguration.class).getClientIdentity().getId());
				});
	}

	@Test
	void configuresIdentityServiceWithX509() {
		runner.withUserConfiguration(EnablePropertiesConfiguration.class)
				.withPropertyValues(
						"sap.security.services.identity.clientid:cid",
						"sap.security.services.identity.certificate:cert", "sap.security.services.identity.key:key")
				.run(context -> {
					assertEquals(CredentialType.X509,
							context.getBean(IdentityServiceConfiguration.class).getCredentialType());
					assertTrue(context.getBean(IdentityServiceConfiguration.class).getClientIdentity()
							.isCertificateBased());
					assertEquals("cert",
							context.getBean(IdentityServiceConfiguration.class).getClientIdentity().getCertificate());
				});
	}
}
