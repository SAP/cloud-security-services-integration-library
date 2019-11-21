package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;

import static com.sap.cloud.security.config.cf.CFEnvironment.*;
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
		cut = new CFEnvironment(fakeSystemEnvironmentProvider, fakeSystemPropertiesProvider);
	}

	@Test
	public void getXsuaaServiceConfiguration() {

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaServiceConfiguration();

		assertThat(serviceConfiguration).isNotNull();
	}

	@Test
	public void getXsuaaServiceConfiguration_usesSystemPropertiesAsFallback() {
		SystemEnvironmentProvider emptyEnvironmentProvider = (str) -> null;
		SystemPropertiesProvider systemPropertiesProvider = (str) -> vcapXsuaa;
		cut = new CFEnvironment(emptyEnvironmentProvider, systemPropertiesProvider);

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaServiceConfiguration();

		assertThat(serviceConfiguration).isNotNull();
	}

	@Test
	public void getXsuaaServiceConfiguration_vcapServicesNotAvilable_returnsNull() {
		SystemEnvironmentProvider emptyEnvironmentProvider = (str) -> null;
		SystemPropertiesProvider emptySystemPropertiesProvider = (str) -> null;
		cut = new CFEnvironment(emptyEnvironmentProvider, emptySystemPropertiesProvider);

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaServiceConfiguration();

		assertThat(serviceConfiguration).isNull();
	}

	private SystemEnvironmentProvider fakeSystemEnvironmentProvider = (String key) -> {
		if (CFConstants.VCAP_SERVICES.equals(key)) {
			return vcapXsuaa;
		}
		return null;
	};

	private SystemPropertiesProvider fakeSystemPropertiesProvider = (String key) -> {
		if (CFConstants.VCAP_SERVICES.equals(key)) {
			return vcapXsuaa;
		}
		return null;
	};

}