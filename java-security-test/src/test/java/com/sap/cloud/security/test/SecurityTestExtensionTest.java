package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class SecurityTestExtensionTest {

	static final int PORT = 4242;
	static final int APPLICATION_SERVER_PORT = 2424;

	@RegisterExtension
	static SecurityTestExtension securityTestExtension = SecurityTestExtension
			.getInstance(Service.XSUAA)
			.setPort(PORT)
			.useApplicationServer(ApplicationServerOptions.forService(Service.XSUAA).usePort(APPLICATION_SERVER_PORT));

	@Test
	void isInitializedAndStartedWithCorrectSettings() {
		SecurityTestConfiguration securityTestConfiguration = securityTestExtension.getConfiguration();

		assertNotNull(securityTestConfiguration);
		assertThat(securityTestConfiguration.getWireMockServer().port()).isEqualTo(PORT);
		assertThat(URI.create(securityTestConfiguration.getApplicationServerUri()).getPort())
				.isEqualTo(APPLICATION_SERVER_PORT);
	}

	@Test
	void resolveSecurityTestConfigurationParameter(SecurityTestConfiguration securityTestConfiguration) {
		assertNotNull(securityTestConfiguration);
		assertThat(securityTestConfiguration.getWireMockServer().port()).isEqualTo(PORT);
		assertThat(URI.create(securityTestConfiguration.getApplicationServerUri()).getPort())
				.isEqualTo(APPLICATION_SERVER_PORT);
	}
}