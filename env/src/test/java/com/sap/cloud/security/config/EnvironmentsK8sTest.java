/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.SapServiceOperatorLayeredServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.DefaultServiceBindingAccessor;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;

import static com.sap.cloud.environment.servicebinding.SapServiceOperatorLayeredServiceBindingAccessor.DEFAULT_PARSING_STRATEGIES;
import static com.sap.cloud.security.config.k8s.K8sConstants.KUBERNETES_SERVICE_HOST;

class EnvironmentsK8sTest {

	private static final String K8S_HOST_VALUE = "0.0.0.0";

	@BeforeAll
	static void beforeAll() {
		Environments.setEnvironmentVariableReader(var -> KUBERNETES_SERVICE_HOST.equals(var) ? K8S_HOST_VALUE : System.getenv(var));
		DefaultServiceBindingAccessor.setInstance(new SapServiceOperatorLayeredServiceBindingAccessor(
				Paths.get(EnvironmentsK8sTest.class.getResource("/k8s").getPath()), DEFAULT_PARSING_STRATEGIES));
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
