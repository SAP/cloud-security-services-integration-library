/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

import com.sap.cloud.security.config.*;
import com.sap.cloud.security.token.TokenExchangeMode;
import com.sap.cloud.security.token.validation.ValidationListener;
import java.util.ArrayList;
import java.util.List;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.jwt.JwtDecoder;

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
  void withTokenExchange() {
    assertNotNull(cut.withTokenExchange(TokenExchangeMode.FORCE_XSUAA));
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