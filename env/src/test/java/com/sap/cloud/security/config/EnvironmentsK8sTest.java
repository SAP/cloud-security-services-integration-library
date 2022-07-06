/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.api.DefaultServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.SapServiceOperatorLayeredServiceBindingAccessor;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.nio.file.Paths;

import static com.sap.cloud.environment.servicebinding.SapServiceOperatorLayeredServiceBindingAccessor.DEFAULT_PARSING_STRATEGIES;
import static com.sap.cloud.security.config.k8s.K8sConstants.KUBERNETES_SERVICE_HOST;

@ExtendWith(SystemStubsExtension.class)
class EnvironmentsK8sTest {

	private static final String K8S_HOST_VALUE = "0.0.0.0";

	@BeforeAll
	static void beforeAll(EnvironmentVariables environmentVariables) {
		environmentVariables.set(KUBERNETES_SERVICE_HOST, K8S_HOST_VALUE);
		DefaultServiceBindingAccessor.setInstance(new SapServiceOperatorLayeredServiceBindingAccessor(
				Paths.get("src/test/resources/k8s"), DEFAULT_PARSING_STRATEGIES));
	}

	@AfterAll
	static void afterAll() {
		DefaultServiceBindingAccessor.setInstance(null);
	}

	@Test
	void getCurrent_returnsOnlySingleK8sInstance() {
		Environment firstEnvironment = Environments.getCurrent();
		Environment secondEnvironment = Environments.getCurrent();

		Assertions.assertThat(firstEnvironment).isSameAs(secondEnvironment);
		Assertions.assertThat(firstEnvironment.getType()).isSameAs(Environment.Type.KUBERNETES);
	}

	@Test
	void getCurrent_returnsK8s() {
		Environment cut = Environments.getCurrent();
		Assertions.assertThat(cut.getType()).isEqualTo(Environment.Type.KUBERNETES);
	}

}
