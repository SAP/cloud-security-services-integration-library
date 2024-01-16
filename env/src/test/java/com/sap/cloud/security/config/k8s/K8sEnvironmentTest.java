/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.environment.servicebinding.SapServiceOperatorLayeredServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.DefaultServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.environment.servicebinding.api.ServiceBindingAccessor;
import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.sap.cloud.environment.servicebinding.SapServiceOperatorLayeredServiceBindingAccessor.DEFAULT_PARSING_STRATEGIES;
import static org.junit.jupiter.api.Assertions.*;

class K8sEnvironmentTest {

	private static Environment cut;

	@BeforeEach
	void beforeEach() {
		DefaultServiceBindingAccessor.setInstance(new SapServiceOperatorLayeredServiceBindingAccessor(
				Paths.get(K8sEnvironmentTest.class.getResource("/k8s").getPath()), DEFAULT_PARSING_STRATEGIES));
	}

	@AfterEach
	void afterEach() {
		K8sEnvironment.instance = null;
		DefaultServiceBindingAccessor.setInstance(null);
	}

	@Test
	void getXsuaaConfiguration() {
		cut = K8sEnvironment.getInstance();
		OAuth2ServiceConfiguration config = cut.getXsuaaConfiguration();
		assertEquals("xsuaaClientId2", config.getClientId());
		assertEquals("uaadomain2.org", config.getProperty(CFConstants.XSUAA.UAA_DOMAIN));
		assertEquals("xsuaa-basic2", config.getProperty(CFConstants.XSUAA.APP_ID));
		assertEquals("xsuaaSecret2", config.getClientSecret());
		assertEquals("https://auth2.sap.com", config.getUrl().toString());
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
		ServiceBinding binding = Mockito.mock(ServiceBinding.class);
		Mockito.when(binding.getServiceName()).thenReturn(Optional.empty());
		Mockito.when(accessor.getServiceBindings()).thenReturn(Collections.singletonList(binding));
		DefaultServiceBindingAccessor.setInstance(accessor);

		cut = K8sEnvironment.getInstance();
		assertEquals(0, cut.getNumberOfXsuaaConfigurations());
		assertNull(cut.getIasConfiguration());
		assertNull(cut.getXsuaaConfiguration());
		assertEquals(2, cut.getServiceConfigurationsAsList().size());
		assertTrue(cut.getServiceConfigurationsAsList().get(Service.XSUAA).isEmpty());
		assertTrue(cut.getServiceConfigurationsAsList().get(Service.IAS).isEmpty());
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
		assertEquals(2, cut.getServiceConfigurationsAsList().size());
		assertTrue(cut.getServiceConfigurationsAsList().get(Service.XSUAA).isEmpty());
		assertTrue(cut.getServiceConfigurationsAsList().get(Service.IAS).isEmpty());
	}

	@Test
	void getNoConfigIfNoServicePlanIsGiven() {
		ServiceBindingAccessor accessor = Mockito.mock(ServiceBindingAccessor.class);
		ServiceBinding binding = Mockito.mock(ServiceBinding.class);
		Mockito.when(binding.getServicePlan()).thenReturn(Optional.empty());
		Mockito.when(accessor.getServiceBindings()).thenReturn(Collections.singletonList(binding));
		DefaultServiceBindingAccessor.setInstance(accessor);

		cut = K8sEnvironment.getInstance();
		assertEquals(0, cut.getNumberOfXsuaaConfigurations());
		assertNull(cut.getIasConfiguration());
		assertNull(cut.getXsuaaConfiguration());
		assertEquals(2, cut.getServiceConfigurationsAsList().size());
		assertTrue(cut.getServiceConfigurationsAsList().get(Service.XSUAA).isEmpty());
		assertTrue(cut.getServiceConfigurationsAsList().get(Service.IAS).isEmpty());
	}
	
	@Test
	void getServiceConfigurationsAsList() {
		cut = K8sEnvironment.getInstance();
		Map<Service, List<OAuth2ServiceConfiguration>> serviceConfigurationsAsList = cut.getServiceConfigurationsAsList();
		assertNotNull(serviceConfigurationsAsList);
		assertEquals(2, serviceConfigurationsAsList.size());
		assertEquals(2, serviceConfigurationsAsList.get(Service.XSUAA).size());
		assertEquals(1, serviceConfigurationsAsList.get(Service.IAS).size());
	}
}