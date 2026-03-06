/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
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
				.withPropertyValues(
						"sap.security.services.identity.url:http://localhost",
						"sap.security.services.identity.clientid:cid",
						"sap.security.services.identity.name:identityInstance0",
						"sap.security.services.identity.plan:broker")
				.run(context -> {
					IdentityServiceConfiguration config = context.getBean(IdentityServiceConfiguration.class);
					assertEquals("http://localhost", config.getUrl().toString());
					assertEquals("cid", config.getClientIdentity().getId());
					assertEquals("identityInstance0", config.getName());
					assertEquals("broker", config.getPlan());
					assertNull(config.getCredentialType());
					assertFalse(config.getClientIdentity().isCertificateBased());
				});
	}

	@Test
	void configuresIdentityServiceWithX509() {
		runner.withUserConfiguration(EnablePropertiesConfiguration.class)
				.withPropertyValues(
						"sap.security.services.identity.clientid:cid",
						"sap.security.services.identity.certificate:cert",
						"sap.security.services.identity.key:key")
				.run(context -> {
					IdentityServiceConfiguration config = context.getBean(IdentityServiceConfiguration.class);
					assertEquals(CredentialType.X509, config.getCredentialType());
					assertTrue(config.getClientIdentity().isCertificateBased());
					assertEquals("cert", config.getClientIdentity().getCertificate());
				});
	}
}
