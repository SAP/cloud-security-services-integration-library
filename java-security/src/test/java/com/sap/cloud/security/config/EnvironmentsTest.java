package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFConstants;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

import static com.sap.cloud.security.config.cf.CFConstants.SERVICE_PLAN;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class EnvironmentsTest {

	private final InputStream vcapMultipleXsuaa;

	public EnvironmentsTest() throws IOException {
		vcapMultipleXsuaa = IOUtils.toInputStream(
				IOUtils.resourceToString("/vcapXsuaaServiceMultipleBindings.json", UTF_8), UTF_8);
	}

	@Test
	public void getCurrent_returnsOnlySingleInstance() {
		Environment firstEnvironment = Environments.getCurrent();
		Environment secondEnvironment = Environments.getCurrent();

		assertThat(firstEnvironment).isSameAs(secondEnvironment);
	}

	@Test
	public void getCurrent_returnsCorrectEnvironment() {
		// TODO 29.11.19 c5295400: extend test when more than one environment is
		// supported
		assertThat(Environments.getCurrent().getType()).isEqualTo(Environment.Type.CF);
	}

	@Test
	public void readFromInputMultipleInstances() {
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
	public void readFromInputDoesNotOverwriteCurrentEnvironment() {
		Environment cut = Environments.readFromInput(vcapMultipleXsuaa);

		assertThat(cut).isNotSameAs(Environments.getCurrent());
	}
}