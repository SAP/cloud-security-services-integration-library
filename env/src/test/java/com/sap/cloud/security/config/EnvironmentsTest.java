/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;


import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static com.sap.cloud.security.config.ServiceConstants.SERVICE_PLAN;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.*;

class EnvironmentsTest {

	private final InputStream vcapMultipleXsuaa;

	EnvironmentsTest() throws IOException {
		vcapMultipleXsuaa = IOUtils.toInputStream(
				IOUtils.resourceToString("/vcapXsuaaServiceMultipleBindings.json", UTF_8), UTF_8);
	}

	@Test
	void getCurrent_isSingleton() {
		Environment firstEnvironment = Environments.getCurrent();
		Environment secondEnvironment = Environments.getCurrent();

		assertThat(firstEnvironment).isSameAs(secondEnvironment);
	}

	@Test
	void readFromInputMultipleInstances() {
		Environment cut = Environments.readFromInput(vcapMultipleXsuaa);

		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(2);
		OAuth2ServiceConfiguration xsuaaConfiguration = cut.getXsuaaConfiguration();
		OAuth2ServiceConfiguration brokerConfiguration = cut.getXsuaaConfigurationForTokenExchange();

		assertThat(xsuaaConfiguration.getService()).isEqualTo(Service.XSUAA);
		assertThat(ServiceConstants.Plan.from(xsuaaConfiguration.getProperty(SERVICE_PLAN)))
				.isEqualTo(ServiceConstants.Plan.APPLICATION);

		assertThat(brokerConfiguration).isNotEqualTo(xsuaaConfiguration);
		assertThat(brokerConfiguration.getService()).isEqualTo(Service.XSUAA);
		assertThat(ServiceConstants.Plan.from(brokerConfiguration.getProperty(SERVICE_PLAN)))
				.isEqualTo(ServiceConstants.Plan.BROKER);
		assertThat(brokerConfiguration).isSameAs(cut.getXsuaaConfigurationForTokenExchange());
	}

	@Test
	void readFromInputDoesNotOverwriteCurrentEnvironment() {
		Environment cut = Environments.readFromInput(vcapMultipleXsuaa);

		assertThat(cut).isNotSameAs(Environments.getCurrent());
	}
}