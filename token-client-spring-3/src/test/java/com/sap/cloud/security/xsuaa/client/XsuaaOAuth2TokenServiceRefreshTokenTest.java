/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;

@ExtendWith(MockitoExtension.class)
public class XsuaaOAuth2TokenServiceRefreshTokenTest {

	private static final String refreshToken = "d2faefe7ea834ba895d20730f106128c-r";

	OAuth2TokenService cut;
	ClientIdentity clientIdentity;
	URI tokenEndpoint;
	Map<String, String> responseMap;

	@Mock
	RestOperations mockRestOperations;

	@BeforeEach
	public void setup() {
		cut = new XsuaaOAuth2TokenService(mockRestOperations);
		clientIdentity = new ClientCredentials("clientid", "mysecretpassword");
		tokenEndpoint = URI.create("https://subdomain.myauth.server.com/oauth/token");

		responseMap = new HashMap<>();
		responseMap.put(REFRESH_TOKEN, "2170b564228448c6aed8b1ddfdb8bf53-r");
		responseMap.put(ACCESS_TOKEN, "f529.dd6e30.d454677322aaabb0");
		responseMap.put(EXPIRES_IN, "43199");
		responseMap.put(TOKEN_TYPE, "bearer");
	}

	@Test
	public void retrieveToken_throwsOnNullValues() {
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaRefreshToken(null, clientIdentity, refreshToken, null, true))
				.isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenEndpointUri");

		assertThatThrownBy(() -> cut.retrieveAccessTokenViaRefreshToken(tokenEndpoint, null, refreshToken, null, true))
				.isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientIdentity");

		assertThatThrownBy(
				() -> cut.retrieveAccessTokenViaRefreshToken(tokenEndpoint, clientIdentity, null, null, true))
				.isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("refreshToken");
	}

	@Test
	public void retrieveToken_throwsIfHttpStatusUnauthorized() {
		Mockito.when(mockRestOperations.postForEntity(eq(tokenEndpoint), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED));

		assertThatThrownBy(() -> cut.retrieveAccessTokenViaRefreshToken(tokenEndpoint, clientIdentity,
				refreshToken, null, true))
				.isInstanceOf(OAuth2ServiceException.class);
	}

	@Test
	public void retrieveToken_throwsIfHttpStatusNotOk() {
		Mockito.when(mockRestOperations.postForEntity(eq(tokenEndpoint), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));

		assertThatThrownBy(() -> cut.retrieveAccessTokenViaRefreshToken(tokenEndpoint, clientIdentity,
				refreshToken, null, true))
				.isInstanceOf(OAuth2ServiceException.class);
	}

	@Test
	public void retrieveToken() throws OAuth2ServiceException {
		TokenServiceHttpEntityMatcher tokenHttpEntityMatcher = new TokenServiceHttpEntityMatcher();
		tokenHttpEntityMatcher.setClientCredentials(clientIdentity);
		tokenHttpEntityMatcher.setGrantType(GRANT_TYPE_REFRESH_TOKEN);
		tokenHttpEntityMatcher.addParameter(REFRESH_TOKEN, refreshToken);

		Mockito.when(mockRestOperations
						.postForEntity(
								eq(tokenEndpoint),
								argThat(tokenHttpEntityMatcher),
								eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		OAuth2TokenResponse accessToken = cut.retrieveAccessTokenViaRefreshToken(tokenEndpoint, clientIdentity,
				refreshToken, null, true);
		assertThat(accessToken.getRefreshToken()).isEqualTo(responseMap.get(REFRESH_TOKEN));
		assertThat(accessToken.getAccessToken()).isEqualTo(responseMap.get(ACCESS_TOKEN));
		assertThat(accessToken.getTokenType()).isEqualTo(responseMap.get(TOKEN_TYPE));
		assertThat(accessToken.getExpiredAt()).isNotNull();
	}
}