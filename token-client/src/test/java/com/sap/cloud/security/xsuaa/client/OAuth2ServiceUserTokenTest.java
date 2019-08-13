package com.sap.cloud.security.xsuaa.client;

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
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.ACCESS_TOKEN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.REFRESH_TOKEN;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;

@RunWith(MockitoJUnitRunner.class)
public class OAuth2ServiceUserTokenTest {

	OAuth2TokenService cut;
	ClientCredentials clientCredentials;
	URI tokenEndpoint;
	Map<String, String> responseMap;
	String userTokenToBeExchanged = "65a84cd45c554c6993ea26cb8f9cf3a2";

	@Mock
	RestTemplate mockRestTemplate;

	@Before
	public void setup() {
		cut = new OAuth2Service(mockRestTemplate);
		clientCredentials = new ClientCredentials("clientid", "mysecretpassword");
		tokenEndpoint = URI.create("https://subdomain.myauth.server.com/oauth/token");

		responseMap = new HashMap<>();
		responseMap.putIfAbsent(REFRESH_TOKEN, "2170b564228448c6aed8b1ddfdb8bf53-r");
		responseMap.putIfAbsent(ACCESS_TOKEN, "4d841646fcc340f59b1b7b43df4b050d"); // opaque access token
		responseMap.putIfAbsent(OAuth2TokenServiceConstants.EXPIRES_IN, "43199");
	}

	@Test(expected = IllegalArgumentException.class)
	public void initialize_throwsIfRestTemplateIsNull() {
		new OAuth2Service(null);
	}

	@Test
	public void retrieveToken_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaUserTokenGrant(null, clientCredentials, userTokenToBeExchanged, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenEndpointUri");

		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, null, userTokenToBeExchanged, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientCredentials");

		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials, null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("token");
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusUnauthorized() {
		Mockito.when(mockRestTemplate.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED));
		cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials,
				userTokenToBeExchanged, null);
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusNotOk() {
		Mockito.when(mockRestTemplate.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));
		cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials,
				userTokenToBeExchanged, null);
	}

	@Test
	public void retrieveToken() {
		HttpHeaders expectedHeaders = new HttpHeaders();
		expectedHeaders.add(HttpHeaders.ACCEPT, "application/json");
		expectedHeaders.add(HttpHeaders.AUTHORIZATION, "Bearer 65a84cd45c554c6993ea26cb8f9cf3a2");
		HttpEntity expectedRequest = new HttpEntity(expectedHeaders);

		Mockito.when(mockRestTemplate
				.postForEntity(eq(createUriWithParameters("grant_type=user_token&client_id=clientid")),
						eq(expectedRequest),
						eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		OAuth2AccessToken accessToken = cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials,
				userTokenToBeExchanged, null);
		assertThat(accessToken.getRefreshToken().get(), is(responseMap.get(REFRESH_TOKEN)));
		assertThat(accessToken.getValue(), is(responseMap.get(ACCESS_TOKEN)));
		assertNotNull(accessToken.getExpiredAtDate());
	}

	@Test
	public void retrieveToken_withOptionalParamaters() {
		Mockito.when(mockRestTemplate.postForEntity(
				eq(createUriWithParameters(
						"grant_type=user_token&add-param-1=value1&add-param-2=value2&client_id=clientid")),
				any(HttpEntity.class), eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		Map<String, String> additionalParameters = new HashMap<>();
		additionalParameters.put("add-param-1", "value1");
		additionalParameters.put("add-param-2", "value2");

		OAuth2AccessToken accessToken = cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials,
				userTokenToBeExchanged, additionalParameters);
		assertThat(accessToken.getRefreshToken().get(), is(responseMap.get(REFRESH_TOKEN)));
	}

	@Test
	public void retrieveToken_requiredParametersCanNotBeOverwritten() {
		Mockito.when(
				mockRestTemplate.postForEntity(eq(createUriWithParameters("grant_type=user_token&client_id=clientid")),
						any(HttpEntity.class), eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		Map<String, String> overwrittenGrantType = new HashMap<>();
		overwrittenGrantType.put(OAuth2TokenServiceConstants.GRANT_TYPE, "overwrite-obligatory-param");

		OAuth2AccessToken accessToken = cut.retrieveAccessTokenViaUserTokenGrant(tokenEndpoint, clientCredentials,
				userTokenToBeExchanged, overwrittenGrantType);
		assertThat(accessToken.getRefreshToken().get(), is(responseMap.get(REFRESH_TOKEN)));
	}

	private URI createUriWithParameters(String queryParameterList) {
		return URI.create(tokenEndpoint.toString() + "?" + queryParameterList);
	}
}