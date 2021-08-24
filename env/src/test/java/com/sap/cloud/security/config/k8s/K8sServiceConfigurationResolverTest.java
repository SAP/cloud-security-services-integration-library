/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.config.Service;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.File;

import static com.sap.cloud.security.config.k8s.K8sConstants.*;
import static com.sap.cloud.security.config.k8s.K8sConstants.SM_CONFIG_PATH;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SystemStubsExtension.class)
class K8sServiceConfigurationResolverTest {

	private static K8sServiceConfigurationResolver cut;

	@BeforeAll
	static void setUp(EnvironmentVariables environmentVariables) {
		String absolutePath = new File("src/test/resources").getAbsolutePath();

		environmentVariables.set(XSUAA_CONFIG_PATH, absolutePath + "/k8s/xsuaa");
		environmentVariables.set(IAS_CONFIG_PATH, absolutePath + "/k8s/ias");
		environmentVariables.set(SM_CONFIG_PATH, absolutePath + "/k8s/service-manager");

		cut = new K8sServiceConfigurationResolver();
	}

	@Test
	void loadServiceManagerConfig() {
		assertEquals("smClientId", cut.loadServiceManagerConfig().getClientId());
	}

	@Test
	void loadOauth2ServiceConfig() {
		assertEquals(2, cut.loadOauth2ServiceConfig(Service.XSUAA).size());
		assertEquals(2, cut.loadOauth2ServiceConfig(Service.IAS).size());
		assertEquals("xsuaaClientId",
				cut.loadOauth2ServiceConfig(Service.XSUAA).get("xsuaa-application").getClientId());
		assertEquals("xsuaaBrokerClientId",
				cut.loadOauth2ServiceConfig(Service.XSUAA).get("xsuaa-broker").getClientId());
		assertEquals("iasClientId", cut.loadOauth2ServiceConfig(Service.IAS).get("ias1").getClientId());
		assertEquals("iasClientId2", cut.loadOauth2ServiceConfig(Service.IAS).get("ias2").getClientId());
	}

	// TODO extend tests with negative test case
}