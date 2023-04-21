package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

class ServiceBindingEnvironmentTest {
	private static ServiceBindingEnvironment cutIas;
	private static ServiceBindingEnvironment cutXsuaa;
	private static ServiceBindingEnvironment cutMultipleXsuaa;

	private static String vcapXsa;

	@BeforeAll
	static void setUp() throws IOException {
		String singleXsuaaConfiguration = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
		String multipleXsuaaConfigurations = IOUtils.resourceToString("/vcapXsuaaServiceMultipleBindings.json", UTF_8);
		String singleIasConfiguration = IOUtils.resourceToString("/vcapIasServiceSingleBinding.json", UTF_8);
		vcapXsa = IOUtils.resourceToString("/vcapXsuaaXsaSingleBinding.json", UTF_8);

		cutIas = new ServiceBindingEnvironment(
				new SapVcapServicesServiceBindingAccessor(any -> singleIasConfiguration));
		cutXsuaa = new ServiceBindingEnvironment(
				new SapVcapServicesServiceBindingAccessor(any -> singleXsuaaConfiguration));
		cutMultipleXsuaa = new ServiceBindingEnvironment(
				new SapVcapServicesServiceBindingAccessor(any -> multipleXsuaaConfigurations));
	}

	@Test
	void getNumberOfXsuaaConfigurations() {
		assertEquals(0, cutIas.getNumberOfXsuaaConfigurations());
		assertEquals(1, cutXsuaa.getNumberOfXsuaaConfigurations());
		assertEquals(2, cutMultipleXsuaa.getNumberOfXsuaaConfigurations());
	}

	@Test
	void getXsuaaConfiguration() {
		assertNull(cutIas.getXsuaaConfiguration());
		assertNotNull(cutXsuaa.getXsuaaConfiguration());
		assertEquals(Service.XSUAA, cutXsuaa.getXsuaaConfiguration().getService());
		assertThat(cutMultipleXsuaa.getXsuaaConfiguration().getProperty(ServiceConstants.SERVICE_PLAN),
				equalToIgnoringCase(ServiceConstants.Plan.APPLICATION.toString()));
	}

	@Test
	void getXsuaaConfigurationForTokenExchange() {
		assertThat(cutMultipleXsuaa.getXsuaaConfigurationForTokenExchange().getProperty(ServiceConstants.SERVICE_PLAN),
				equalToIgnoringCase(ServiceConstants.Plan.BROKER.toString()));
		assertNotSame(cutMultipleXsuaa.getXsuaaConfigurationForTokenExchange(),
				cutMultipleXsuaa.getXsuaaConfiguration());

		assertThat(cutXsuaa.getXsuaaConfigurationForTokenExchange().getProperty(ServiceConstants.SERVICE_PLAN),
				equalToIgnoringCase(ServiceConstants.Plan.APPLICATION.toString()));
		assertSame(cutXsuaa.getXsuaaConfigurationForTokenExchange(), cutXsuaa.getXsuaaConfiguration());

		assertNull(cutIas.getXsuaaConfigurationForTokenExchange());
	}

	@Test
	void getIasConfiguration() {
		assertNull(cutXsuaa.getIasConfiguration());
		assertNotNull(cutIas.getIasConfiguration());
		assertThat(cutIas.getIasConfiguration().getService(), equalTo(Service.IAS));
		assertThat(cutIas.getIasConfiguration().getClientId(), equalTo("T000310"));
		assertThat(cutIas.getIasConfiguration().getClientSecret(), startsWith("pCghfbrL"));
		assertThat(cutIas.getIasConfiguration().getDomains(), hasSize(2));
		assertFalse(cutIas.getIasConfiguration().isLegacyMode());
	}

	@Test
	void getServiceConfigurations() {
		Map<Service, Map<ServiceConstants.Plan, OAuth2ServiceConfiguration>> configs = cutIas
				.getServiceConfigurations();
		assertThat(configs.get(Service.XSUAA).entrySet(), is((empty())));
		assertThat(configs.get(Service.IAS).entrySet(), hasSize(1));

		configs = cutXsuaa.getServiceConfigurations();
		assertThat(configs.get(Service.XSUAA).entrySet(), hasSize(1));
		assertThat(configs.get(Service.IAS).entrySet(), is(empty()));

		configs = cutMultipleXsuaa.getServiceConfigurations();
		assertThat(configs.get(Service.XSUAA).entrySet(), hasSize(2));
		assertThat(configs.get(Service.IAS).entrySet(), is(empty()));
	}

	@Test
	void getConfigurationOfXsuaaInstanceInXsaSystem() {
		ServiceBindingEnvironment cut = new ServiceBindingEnvironment(
				new SapVcapServicesServiceBindingAccessor(any -> vcapXsa))
				.withEnvironmentVariableReader(vcap_application -> "{\"xs_api\" : \"\"}");

		assertEquals(Service.XSUAA, cut.getXsuaaConfiguration().getService());
		assertEquals(ServiceConstants.Plan.SPACE,
				ServiceConstants.Plan.from(cut.getXsuaaConfiguration().getProperty(ServiceConstants.SERVICE_PLAN)));
		assertEquals("java-hello-world!i1", cut.getXsuaaConfiguration().getProperty(ServiceConstants.XSUAA.APP_ID));
		assertTrue(cut.getXsuaaConfiguration().isLegacyMode());

		assertEquals(1, cut.getNumberOfXsuaaConfigurations());
		assertThat(cut.getXsuaaConfigurationForTokenExchange(), sameInstance(cut.getXsuaaConfiguration()));
	}
}