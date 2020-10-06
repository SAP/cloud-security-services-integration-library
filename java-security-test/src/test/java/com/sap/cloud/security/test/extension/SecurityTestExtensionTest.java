package com.sap.cloud.security.test.extension;

import com.sap.cloud.security.test.ApplicationServerOptions;
import com.sap.cloud.security.test.SecurityTestContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.URI;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class SecurityTestExtensionTest {

	static final int PORT = 4242;
	static final int APPLICATION_SERVER_PORT = 2424;

	@RegisterExtension
	static SecurityTestExtension securityTestExtension = SecurityTestExtension.forService(XSUAA)
			.setPort(PORT)
			.useApplicationServer(ApplicationServerOptions.forService(XSUAA).usePort(APPLICATION_SERVER_PORT));

	@Test
	void isInitializedAndStartedWithCorrectSettings() {
		SecurityTestContext context = securityTestExtension.getContext();

		assertNotNull(context);
		assertThat(context.getWireMockServer().port()).isEqualTo(PORT);
		assertThat(URI.create(context.getApplicationServerUri()).getPort())
				.isEqualTo(APPLICATION_SERVER_PORT);
	}

	@Test
	void resolveSecurityTestConfigurationParameter(SecurityTestContext context) {
		assertNotNull(context);
		assertThat(context.getWireMockServer().port()).isEqualTo(PORT);
		assertThat(URI.create(context.getApplicationServerUri()).getPort())
				.isEqualTo(APPLICATION_SERVER_PORT);
	}
}