/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.environment.servicebinding.SapServiceOperatorLayeredServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.DefaultServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.environment.servicebinding.api.ServiceBindingAccessor;
import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;

import javax.annotation.Nonnull;
import java.nio.file.Paths;
import java.util.*;

import static com.sap.cloud.environment.servicebinding.SapServiceOperatorLayeredServiceBindingAccessor.DEFAULT_PARSING_STRATEGIES;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class K8sEnvironmentTest {

	private static Environment cut;

	@BeforeAll
	static void beforeAll() {
		DefaultServiceBindingAccessor.setInstance(new SapServiceOperatorLayeredServiceBindingAccessor(
				Paths.get(K8sEnvironmentTest.class.getResource("/k8s").getPath()), DEFAULT_PARSING_STRATEGIES));
	}

	@AfterAll
	static void afterAll() {
		DefaultServiceBindingAccessor.setInstance(null);
	}

	@Test
	void getXsuaaConfiguration() {
		cut = K8sEnvironment.getInstance();
		OAuth2ServiceConfiguration config = cut.getXsuaaConfiguration();
		assertEquals("xsuaaClientId", config.getClientId());
		assertEquals("uaadomain.org", config.getProperty(CFConstants.XSUAA.UAA_DOMAIN));
		assertEquals("xsuaa-basic", config.getProperty(CFConstants.XSUAA.APP_ID));
		assertEquals("xsuaaSecret", config.getClientSecret());
		assertEquals("https://auth.sap.com", config.getUrl().toString());
	}

	@Test
	void getIasConfiguration() {
		cut = K8sEnvironment.getInstance();
		OAuth2ServiceConfiguration config = cut.getIasConfiguration();
		assertEquals("iasClientId2", config.getClientId());
		assertEquals("domain1.sap.com", config.getDomains().get(0));
		assertEquals("domain2.sap.com", config.getDomains().get(1));
		assertEquals("sec\\\"re?%$@#t\"='`", config.getClientSecret());
	}

	@Test
	void getNumberOfXsuaaConfigurations() {
		cut = K8sEnvironment.getInstance();
		assertEquals(2, cut.getNumberOfXsuaaConfigurations());
	}

	@Test
	void getXsuaaConfigurationForTokenExchange() {
		cut = K8sEnvironment.getInstance();
		OAuth2ServiceConfiguration config = cut.getXsuaaConfigurationForTokenExchange();
		assertEquals("xsuaaBrokerClientId", config.getClientId());
		assertEquals("uaadomain.org", config.getProperty(CFConstants.XSUAA.UAA_DOMAIN));
		assertEquals("xsuaa-broker", config.getProperty(CFConstants.XSUAA.APP_ID));
	}

	@Test
	void getNoConfigIfNoServiceNameIsGiven() {
		ServiceBindingAccessor accessor = Mockito.mock(ServiceBindingAccessor.class);
		List<ServiceBinding> bindings = new ArrayList();
		ServiceBinding binding = Mockito.mock(ServiceBinding.class);
		Mockito.when(binding.getServiceName()).thenReturn(Optional.empty());
		bindings.add(binding);
		Mockito.when(accessor.getServiceBindings()).thenReturn(bindings);
		DefaultServiceBindingAccessor.setInstance(accessor);

		cut = K8sEnvironment.getInstance();
		assertEquals(0, cut.getNumberOfXsuaaConfigurations());
		assertNull(cut.getIasConfiguration());
		assertNull(cut.getXsuaaConfiguration());
	}

	@Test
	void getNoConfigIfNoServicesAreGiven() {
		ServiceBindingAccessor accessor = Mockito.mock(ServiceBindingAccessor.class);
		Mockito.when(accessor.getServiceBindings()).thenReturn(Collections.emptyList());
		DefaultServiceBindingAccessor.setInstance(accessor);

		cut = K8sEnvironment.getInstance();
		assertEquals(0, cut.getNumberOfXsuaaConfigurations());
		assertNull(cut.getIasConfiguration());
		assertNull(cut.getXsuaaConfiguration());
	}

	@Test
	void getNoConfigIfNoServicePlanIsGiven() {
		ServiceBindingAccessor accessor = Mockito.mock(ServiceBindingAccessor.class);
		List<ServiceBinding> bindings = new ArrayList();
		ServiceBinding binding = Mockito.mock(ServiceBinding.class);
		Mockito.when(binding.getServicePlan()).thenReturn(Optional.empty());
		bindings.add(binding);
		Mockito.when(accessor.getServiceBindings()).thenReturn(bindings);
		DefaultServiceBindingAccessor.setInstance(accessor);

		cut = K8sEnvironment.getInstance();
		assertEquals(0, cut.getNumberOfXsuaaConfigurations());
		assertNull(cut.getIasConfiguration());
		assertNull(cut.getXsuaaConfiguration());
	}

}