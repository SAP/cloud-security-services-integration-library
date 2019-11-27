package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class CFEnvironmentTest {

	private String vcapXsuaa;
	private CFEnvironment cut;

	public CFEnvironmentTest() throws IOException {
		vcapXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
	}

	@Before
	public void setUp() {
		cut = CFEnvironment.getInstance((str) -> vcapXsuaa, (str) -> vcapXsuaa);
	}

	@Test
	public void getXsuaaServiceConfiguration() {

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaServiceConfiguration();

		assertThat(serviceConfiguration).isNotNull();
	}

	@Test
	public void getXsuaaServiceConfiguration_usesSystemPropertiesAsFallback() {
		cut = CFEnvironment.getInstance((str) -> null, (str) -> vcapXsuaa);

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaServiceConfiguration();

		assertThat(serviceConfiguration).isNotNull();
	}

	@Test
	public void getXsuaaServiceConfiguration_vcapServicesNotAvailable_returnsNull() {
		cut = CFEnvironment.getInstance((str) -> null, (str) -> null);

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaServiceConfiguration();

		assertThat(serviceConfiguration).isNull();
	}
}