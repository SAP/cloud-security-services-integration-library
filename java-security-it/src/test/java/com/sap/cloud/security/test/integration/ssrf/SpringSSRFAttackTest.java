/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.integration.ssrf;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.RSAKeys;
import com.sap.cloud.security.test.SecurityTest;
import com.sap.cloud.security.test.extension.SecurityTestExtension;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.xsuaa.XsuaaCredentials;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationCustom;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test cases for <a href=
 * "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery">SSRF
 * (Server Side Request Forgery)</a> attacks.
 */
class SpringSSRFAttackTest {

	private RestOperations restOperations = Mockito.spy(new RestTemplate());

	@RegisterExtension
	static SecurityTestExtension extension = SecurityTestExtension.forService(Service.XSUAA).setPort(4242);

	/**
	 * This tests checks that an attacker cannot trick the token validation into
	 * using his/her own token key server by manipulating the JWKS url. The
	 * challenge is to redirect the request to a different token key server without
	 * the token validation steps to fail.
	 *
	 * @param jwksUrl
	 *            the JWKS url containing malicious parts
	 * @param isValid
	 *            {@code true} if the token validation is expected to be successful
	 */
	@ParameterizedTest
	@CsvSource({
			"http://localhost:4242/token_keys@malicious.ondemand.com/token_keys,		false",
			"http://malicious.ondemand.com@localhost:4242/token_keys,					true",
			"http://localhost:4242/token_keys///malicious.ondemand.com/token_keys,		false",
	})
	void maliciousPartOfJwksIsNotUsedToObtainToken(String jwksUrl, boolean isValid)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String token;
		if (isValid) {
			token = extension.getContext().getPreconfiguredJwtGenerator()
					.withHeaderParameter(TokenHeader.JWKS_URL, jwksUrl)
					.createToken()
					.getTokenValue();
		} else {
			token = extension.getContext().getPreconfiguredJwtGenerator()
					.withHeaderParameter(TokenHeader.JWKS_URL, jwksUrl)
					.withPrivateKey(RSAKeys.loadPrivateKey("/random_private_key.txt"))
					.createToken()
					.getTokenValue();
		}
		JwtDecoder jwtDecoder = new XsuaaJwtDecoderBuilder(
				new XsuaaServiceConfigurationCustom(createXsuaaCredentials()))
						.withRestOperations(restOperations)
						.build();
		try {
			jwtDecoder.decode(token);
			assertThat(isValid).isTrue();
		} catch (JwtException e) {
			assertThat(isValid).isFalse();
		}
		ArgumentCaptor<RequestEntity> requestArgumentCaptor = ArgumentCaptor.forClass(RequestEntity.class);
		Mockito.verify(restOperations).exchange(requestArgumentCaptor.capture(),
				ArgumentCaptor.forClass(Class.class).capture());
		String host = requestArgumentCaptor.getValue().getUrl().getHost();
		assertThat(host).isEqualTo("localhost");
	}

	private XsuaaCredentials createXsuaaCredentials() {
		XsuaaCredentials xsuaaCredentials = new XsuaaCredentials();
		xsuaaCredentials.setUaaDomain(extension.getContext().getWireMockServer().baseUrl());
		xsuaaCredentials.setClientId(SecurityTest.DEFAULT_CLIENT_ID);
		xsuaaCredentials.setXsAppName(SecurityTest.DEFAULT_APP_ID);
		return xsuaaCredentials;
	}
}
