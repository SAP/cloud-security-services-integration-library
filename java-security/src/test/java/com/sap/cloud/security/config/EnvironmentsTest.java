/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFConstants;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.IOException;
import java.io.InputStream;

import static com.sap.cloud.security.config.cf.CFConstants.SERVICE_PLAN;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SystemStubsExtension.class)
class EnvironmentsTest {

	private static final String KUBERNETES_SERVICE_HOST = "KUBERNETES_SERVICE_HOST";
	private static final String K8S_HOST_VALUE = "0.0.0.0";
	private final InputStream vcapMultipleXsuaa;

	public EnvironmentsTest() throws IOException {
		vcapMultipleXsuaa = IOUtils.toInputStream(
				IOUtils.resourceToString("/vcapXsuaaServiceMultipleBindings.json", UTF_8), UTF_8);
	}

	@Test
	void getCurrent_returnsOnlySingleCFInstance() {
		Environment firstEnvironment = Environments.getCurrent();
		Environment secondEnvironment = Environments.getCurrent();

		assertThat(firstEnvironment).isSameAs(secondEnvironment);
	}

	@Test
	 void getCurrent_returnsOnlySingleK8sInstance(EnvironmentVariables environmentVariables) {
		environmentVariables.set(KUBERNETES_SERVICE_HOST, K8S_HOST_VALUE);

		Environment firstEnvironment = Environments.getCurrent();
		Environment secondEnvironment = Environments.getCurrent();

		assertThat(firstEnvironment).isSameAs(secondEnvironment);
		assertThat(firstEnvironment.getType()).isSameAs(Environment.Type.KUBERNETES);
	}

	@Test
	 void getCurrent_returnsCf() {
		assertThat(Environments.getCurrent().getType()).isEqualTo(Environment.Type.CF);
	}

	@Test
	void getCurrent_returnsK8s(EnvironmentVariables environmentVariables) {
		environmentVariables.set(KUBERNETES_SERVICE_HOST, K8S_HOST_VALUE);
		Environment cut = Environments.getCurrent();
		assertThat(cut.getType()).isEqualTo(Environment.Type.KUBERNETES);
	}

	@Test
	 void readFromInputMultipleInstances() {
		Environment cut = Environments.readFromInput(vcapMultipleXsuaa);

		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(2);
		OAuth2ServiceConfiguration appServConfig = cut.getXsuaaConfiguration();
		OAuth2ServiceConfiguration brokerServConfig = cut.getXsuaaConfigurationForTokenExchange();

		assertThat(appServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(CFConstants.Plan.from(appServConfig.getProperty(SERVICE_PLAN)))
				.isEqualTo(CFConstants.Plan.APPLICATION);

		assertThat(brokerServConfig).isNotEqualTo(appServConfig);
		assertThat(brokerServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(CFConstants.Plan.from(brokerServConfig.getProperty(SERVICE_PLAN)))
				.isEqualTo(CFConstants.Plan.BROKER);
		assertThat(brokerServConfig).isSameAs(cut.getXsuaaConfigurationForTokenExchange());
	}

	@Test
	 void readFromInputDoesNotOverwriteCurrentEnvironment() {
		Environment cut = Environments.readFromInput(vcapMultipleXsuaa);

		assertThat(cut).isNotSameAs(Environments.getCurrent());
	}
}
