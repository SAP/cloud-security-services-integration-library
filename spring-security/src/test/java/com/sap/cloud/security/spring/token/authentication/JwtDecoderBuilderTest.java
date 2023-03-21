/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.token.validation.ValidationListener;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class JwtDecoderBuilderTest {
	JwtDecoderBuilder cut = new JwtDecoderBuilder();

	@Test
	void withCacheConfiguration() {
		CacheConfiguration cacheConfiguration = Mockito.mock(CacheConfiguration.class);
		assertNotNull(cut.withCacheConfiguration(cacheConfiguration));
	}

	@Test
	void withHttpClient() {
		CloseableHttpClient mockHttpClient = Mockito.mock(CloseableHttpClient.class);
		assertNotNull(cut.withHttpClient(mockHttpClient));
	}

	@Test
	void buildWithoutConfiguration_IllegalStateException() {
		assertThrows(IllegalStateException.class, () -> cut.build());
	}

	@Test
	void buildHybridWithConfigurations() {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withClientId("clientId")
				.withProperty(ServiceConstants.URL, "https://domain.myauth.com")
				.build();

		cut.withIasServiceConfiguration(configuration);
		cut.withXsuaaServiceConfiguration(configuration);
		cut.withValidationListener(Mockito.mock(ValidationListener.class));
		JwtDecoder decoder = cut.build();
		assertTrue(decoder instanceof HybridJwtDecoder);
	}

	@Test
	void buildHybridWithMultipleXsuaaConfigurations() {
		OAuth2ServiceConfiguration iasConfiguration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withClientId("clientId")
				.withProperty(ServiceConstants.URL, "https://domain.myauth.com")
				// .withProperty(CFConstants.IAS.DOMAIN, "myauth.com")
				.build();

		OAuth2ServiceConfiguration otherXsuaaConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(otherXsuaaConfiguration.getClientId()).thenReturn("otherClientId");

		List<OAuth2ServiceConfiguration> xsuaaConfigurations = new ArrayList<>();
		xsuaaConfigurations.add(iasConfiguration);
		xsuaaConfigurations.add(otherXsuaaConfiguration);

		cut.withIasServiceConfiguration(iasConfiguration);
		cut.withXsuaaServiceConfigurations(xsuaaConfigurations);
		cut.withValidationListener(Mockito.mock(ValidationListener.class));
		JwtDecoder decoder = cut.build();
		assertTrue(decoder instanceof HybridJwtDecoder);
	}
}