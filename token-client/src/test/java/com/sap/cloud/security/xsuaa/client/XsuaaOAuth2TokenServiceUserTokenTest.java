/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaOAuth2TokenServiceUserTokenTest {

	OAuth2TokenService cut;
	ClientIdentity clientIdentity;
	URI tokenEndpoint;
	Map<String, String> responseMap;
	private static final String userTokenToBeExchanged = "65a84cd45c554c6993ea26cb8f9cf3a2";

	@Mock
	RestOperations mockRestOperations;

	@Before
	public void setup() {
		cut = new XsuaaOAuth2TokenService(mockRestOperations);
		clientIdentity = new ClientCredentials("clientid", "mysecretpassword");
		tokenEndpoint = URI.create("https://subdomain.myauth.server.com/oauth/token");

		responseMap = new HashMap<>();
		responseMap.put(REFRESH_TOKEN, "2170b564228448c6aed8b1ddfdb8bf53-r");
		responseMap.put(ACCESS_TOKEN, "4d841646fcc340f59b1b7b43df4b050d"); // opaque access token
		responseMap.put(EXPIRES_IN, "43199");
		responseMap.put(TOKEN_TYPE, "bearer");
	}

	@Test
	public void retrieveToken_throwsOnNullValues() {
		assertThatThrownBy(() -> cut.retrieveAccessTokenViaJwtBearerTokenGrant(null, clientIdentity, userTokenToBeExchanged,
				null, null, true)).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenEndpoint");

		assertThatThrownBy(
				() -> cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, null, userTokenToBeExchanged, null, null, true))
						.isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientIdentity");

		assertThatThrownBy(
				() -> cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientIdentity, null, null, null, true))
						.isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("token");
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusUnauthorized() throws OAuth2ServiceException {
		Mockito.when(mockRestOperations.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED));
		cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientIdentity,
				userTokenToBeExchanged, null, null, true);
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusNotOk() throws OAuth2ServiceException {
		Mockito.when(mockRestOperations.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));
		cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientIdentity,
				userTokenToBeExchanged, null, null, true);
	}

	@Test
	public void retrieveToken() throws OAuth2ServiceException {
		TokenServiceHttpEntityMatcher tokenHttpEntityMatcher = new TokenServiceHttpEntityMatcher();
		tokenHttpEntityMatcher.setGrantType(OAuth2TokenServiceConstants.GRANT_TYPE_JWT_BEARER);
		tokenHttpEntityMatcher.addParameter(OAuth2TokenServiceConstants.PARAMETER_CLIENT_ID, clientIdentity.getId());

		HttpHeaders expectedHeaders = new HttpHeaders();
		expectedHeaders.add(HttpHeaders.ACCEPT, "application/json");
		expectedHeaders.add(HttpHeaders.AUTHORIZATION, "Bearer " + userTokenToBeExchanged);
		HttpEntity expectedRequest = new HttpEntity(expectedHeaders);

		Mockito.when(mockRestOperations
				.postForEntity(
						eq(tokenEndpoint),
						argThat(tokenHttpEntityMatcher),
						eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		OAuth2TokenResponse accessToken = cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientIdentity,
				userTokenToBeExchanged, null, null, true);
		assertThat(accessToken.getRefreshToken(), is(responseMap.get(REFRESH_TOKEN)));
		assertThat(accessToken.getAccessToken(), is(responseMap.get(ACCESS_TOKEN)));
		assertThat(accessToken.getTokenType(), is(responseMap.get(TOKEN_TYPE)));
		assertNotNull(accessToken.getExpiredAt());
	}

	@Test
	public void retrieveToken_withOptionalParamaters() throws OAuth2ServiceException {
		Map<String, String> additionalParameters = new HashMap<>();
		additionalParameters.put("add-param-1", "value1");
		additionalParameters.put("add-param-2", "value2");

		TokenServiceHttpEntityMatcher tokenHttpEntityMatcher = new TokenServiceHttpEntityMatcher();
		tokenHttpEntityMatcher.setGrantType(GRANT_TYPE_JWT_BEARER);
		tokenHttpEntityMatcher.addParameter(OAuth2TokenServiceConstants.PARAMETER_CLIENT_ID, clientIdentity.getId());
		tokenHttpEntityMatcher.addParameters(additionalParameters);

		Mockito.when(mockRestOperations.postForEntity(
				eq(tokenEndpoint),
				argThat(tokenHttpEntityMatcher),
				eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		OAuth2TokenResponse accessToken = cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientIdentity,
				userTokenToBeExchanged, null, additionalParameters, true);
		assertThat(accessToken.getRefreshToken(), is(responseMap.get(REFRESH_TOKEN)));
	}

	@Test
	public void retrieveToken_requiredParametersCanNotBeOverwritten() throws OAuth2ServiceException {
		TokenServiceHttpEntityMatcher tokenHttpEntityMatcher = new TokenServiceHttpEntityMatcher();
		tokenHttpEntityMatcher.setGrantType(OAuth2TokenServiceConstants.GRANT_TYPE_JWT_BEARER);
		tokenHttpEntityMatcher.addParameter(OAuth2TokenServiceConstants.PARAMETER_CLIENT_ID, clientIdentity.getId());

		Mockito.when(
				mockRestOperations.postForEntity(
						eq(tokenEndpoint),
						argThat(tokenHttpEntityMatcher),
						eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		Map<String, String> overwrittenGrantType = new HashMap<>();
		overwrittenGrantType.put(OAuth2TokenServiceConstants.GRANT_TYPE, "overwrite-obligatory-param");

		OAuth2TokenResponse accessToken = cut.retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpoint, clientIdentity,
				userTokenToBeExchanged, null, overwrittenGrantType, true);
		assertThat(accessToken.getRefreshToken(), is(responseMap.get(REFRESH_TOKEN)));
	}
}