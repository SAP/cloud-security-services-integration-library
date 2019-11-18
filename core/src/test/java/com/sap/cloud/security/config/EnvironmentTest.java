package com.sap.cloud.security.config;

import com.sap.cloud.security.config.Environment.SystemEnvironmentProvider;
import com.sap.cloud.security.config.cf.CFConstants;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static com.sap.cloud.security.config.Environment.SystemPropertiesProvider;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class EnvironmentTest {

	private String vcapXsuaa;
	private Environment cut;

	public EnvironmentTest() throws IOException {
		vcapXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
	}

	@Before
	public void setUp() {
		cut = new Environment(fakeSystemEnvironmentProvider, fakeSystemPropertiesProvider);
	}

	@Test
	public void getInstance() {
		Environment firstInstance = Environment.getInstance();
		Environment anotherInstance = Environment.getInstance();

		assertThat(firstInstance).isSameAs(anotherInstance);
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
		cut = new Environment(emptyEnvironmentProvider, systemPropertiesProvider);

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaServiceConfiguration();

		assertThat(serviceConfiguration).isNotNull();
	}

	@Test
	public void getXsuaaServiceConfiguration_vcapServicesNotAvilable_returnsNull() {
		SystemEnvironmentProvider emptyEnvironmentProvider = (str) -> null;
		SystemPropertiesProvider emptySystemPropertiesProvider = (str) -> null;
		cut = new Environment(emptyEnvironmentProvider, emptySystemPropertiesProvider);

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