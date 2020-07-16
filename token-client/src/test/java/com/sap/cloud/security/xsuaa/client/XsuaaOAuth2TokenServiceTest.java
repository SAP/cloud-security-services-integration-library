package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.web.client.RestOperations;

public class XsuaaOAuth2TokenServiceTest {

	@Test(expected = IllegalArgumentException.class)
	public void initialize_throwsIfRestOperationsIsNull() {
		new XsuaaOAuth2TokenService(null, TokenCacheConfiguration.cacheDisabled());
	}

	@Test(expected = IllegalArgumentException.class)
	public void initialize_throwsIfCacheConfigurationIsNull() {
		new XsuaaOAuth2TokenService(Mockito.mock(RestOperations.class), null);
	}

}