/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.ACCESS_TOKEN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.EXPIRES_IN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE_REFRESH_TOKEN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.REFRESH_TOKEN;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import com.sap.cloud.security.config.ClientCredentials;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaOAuth2TokenServiceRefreshTokenTest {

	private static String refreshToken = "d2faefe7ea834ba895d20730f106128c-r";

	OAuth2TokenService cut;
	ClientCredentials clientCredentials;
	URI tokenEndpoint;
	Map<String, String> responseMap;

	@Mock
	RestOperations mockRestOperations;

	@Before
	public void setup() {
		cut = new XsuaaOAuth2TokenService(mockRestOperations);
		clientCredentials = new ClientCredentials("clientid", "mysecretpassword");
		tokenEndpoint = URI.create("https://subdomain.myauth.server.com/oauth/token");

		responseMap = new HashMap<>();
		responseMap.put(REFRESH_TOKEN, "2170b564228448c6aed8b1ddfdb8bf53-r");
		responseMap.put(ACCESS_TOKEN, "f529.dd6e30.d454677322aaabb0");
		responseMap.put(EXPIRES_IN, "43199");
	}

	@Test
	public void retrieveToken_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaRefreshToken(null, clientCredentials, refreshToken, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenEndpointUri");

		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaRefreshToken(tokenEndpoint, null, refreshToken, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientIdentity");

		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaRefreshToken(tokenEndpoint, clientCredentials, null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("refreshToken");
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusUnauthorized() throws OAuth2ServiceException {
		Mockito.when(mockRestOperations.postForEntity(eq(tokenEndpoint), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED));
		cut.retrieveAccessTokenViaRefreshToken(tokenEndpoint, clientCredentials,
				refreshToken, null);
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusNotOk() throws OAuth2ServiceException {
		Mockito.when(mockRestOperations.postForEntity(eq(tokenEndpoint), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));
		cut.retrieveAccessTokenViaRefreshToken(tokenEndpoint, clientCredentials,
				refreshToken, null);
	}

	@Test
	public void retrieveToken() throws OAuth2ServiceException {
		TokenServiceHttpEntityMatcher tokenHttpEntityMatcher = new TokenServiceHttpEntityMatcher();
		tokenHttpEntityMatcher.setClientCredentials(clientCredentials);
		tokenHttpEntityMatcher.setGrantType(GRANT_TYPE_REFRESH_TOKEN);
		tokenHttpEntityMatcher.addParameter(REFRESH_TOKEN, refreshToken);

		Mockito.when(mockRestOperations
				.postForEntity(
						eq(tokenEndpoint),
						argThat(tokenHttpEntityMatcher),
						eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		OAuth2TokenResponse accessToken = cut.retrieveAccessTokenViaRefreshToken(tokenEndpoint, clientCredentials,
				refreshToken, null);
		assertThat(accessToken.getRefreshToken(), is(responseMap.get(REFRESH_TOKEN)));
		assertThat(accessToken.getAccessToken(), is(responseMap.get(ACCESS_TOKEN)));
		assertNotNull(accessToken.getExpiredAtDate());
	}
}