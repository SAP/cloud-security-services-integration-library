package com.sap.cloud.security.servlet;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.Test;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IasXsuaaExchangeBrokerTest {

	@Test
	void doIasToXsuaaXchange_ConfigurationIsNull() {
		assertThrows(
				IllegalArgumentException.class,
				() -> IasXsuaaExchangeBroker.build(null, new DefaultOAuth2TokenService(HttpClientFactory.create(null))),
				"Service configuration must not be null");

		assertThrows(
				IllegalArgumentException.class,
				() -> IasXsuaaExchangeBroker.build(OAuth2ServiceConfigurationBuilder.forService(XSUAA).build(), null),
				"OAuth Token Service must not be null");

		assertThrows(
				IllegalArgumentException.class,
				() -> IasXsuaaExchangeBroker.build(OAuth2ServiceConfigurationBuilder.forService(XSUAA).build(),
						new DefaultOAuth2TokenService((CloseableHttpClient) null)),
				"Http Client must not be null");
	}
}