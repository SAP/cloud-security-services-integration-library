package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFConstants;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class EnvironmentTest {

	private String vcapXsuaa = null;
	private Environment cut;

	private Environment.SystemEnvironmentProvider fakeSystemEnvironmentProvider = (String key) -> {
		if (CFConstants.VCAP_SERVICES.equals(key)) {
			return vcapXsuaa;
		}
		return null;
	};

	public EnvironmentTest() throws IOException {
		vcapXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
	}

	@Before
	public void setUp() {
		cut = new Environment(fakeSystemEnvironmentProvider);
	}

	@Test
	public void getInstance() {
		Environment firstInstance = Environment.getInstance();
		Environment anotherInstance = Environment.getInstance();

		assertThat(firstInstance).isSameAs(anotherInstance);
	}

	@Test
	public void overrideOAuth2ServiceConfiguration() {
		OAuth2ServiceConfiguration serviceConfigMock = Mockito.mock(OAuth2ServiceConfiguration.class);

		cut.setOAuth2ServiceConfiguration(serviceConfigMock);

		assertThat(cut.getXsuaaServiceConfiguration()).isEqualTo(serviceConfigMock);
	}

	@Test
	public void getXsuaaServiceConfiguration() {

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaServiceConfiguration();

		assertThat(serviceConfiguration).isNotNull();
	}
}