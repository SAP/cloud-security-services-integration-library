package com.sap.cloud.security.xsuaa.client;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.hamcrest.CoreMatchers.is;

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

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.ACCESS_TOKEN;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.any;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaOAuth2TokenServiceClientCredentialsTest {

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
		responseMap.putIfAbsent(ACCESS_TOKEN, "f529.dd6e30.d454677322aaabb0");
		responseMap.putIfAbsent(OAuth2TokenServiceConstants.EXPIRES_IN, "43199");
	}

	@Test(expected = IllegalArgumentException.class)
	public void initialize_throwsIfRestOperationsIsNull() {
		new XsuaaOAuth2TokenService(null);
	}

	@Test
	public void retrieveToken_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaClientCredentialsGrant(null, clientCredentials, null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenEndpointUri");

		assertThatThrownBy(() -> {
			cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint, null, null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("clientCredentials");
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusUnauthorized() {
		Mockito.when(mockRestOperations.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED));
		cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint, clientCredentials,
				null, null);
	}

	@Test(expected = OAuth2ServiceException.class)
	public void retrieveToken_throwsIfHttpStatusNotOk() {
		Mockito.when(mockRestOperations.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));
		cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint, clientCredentials,
				null, null);
	}

	@Test
	public void retrieveToken() {
		HttpHeaders expectedHeaders = new HttpHeaders();
		expectedHeaders.add(HttpHeaders.ACCEPT, "application/json");
		HttpEntity expectedRequest = new HttpEntity(expectedHeaders);

		Mockito.when(mockRestOperations
				.postForEntity(
						eq(createUriWithParameters(
								"grant_type=client_credentials&client_secret=mysecretpassword&client_id=clientid")),
						eq(expectedRequest),
						eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		OAuth2AccessToken accessToken = cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint,
				clientCredentials,
				null, null);
		assertThat(accessToken.getValue(), is(responseMap.get(ACCESS_TOKEN)));
		assertNotNull(accessToken.getExpiredAtDate());
	}

	@Test
	public void retrieveToken_withOptionalParamaters() {
		Mockito.when(mockRestOperations.postForEntity(
				eq(createUriWithParameters(
						"add-param-1=value1&add-param-2=value2&client_secret=mysecretpassword&grant_type=client_credentials&client_id=clientid")),
				any(HttpEntity.class), eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		Map<String, String> additionalParameters = new HashMap<>();
		additionalParameters.put("add-param-1", "value1");
		additionalParameters.put("add-param-2", "value2");

		OAuth2AccessToken accessToken = cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint,
				clientCredentials, null,
				additionalParameters);
		assertThat(accessToken.getValue(), is(responseMap.get(ACCESS_TOKEN)));
	}

	@Test
	public void retrieveToken_requiredParametersCanNotBeOverwritten() {
		Mockito.when(mockRestOperations.postForEntity(
				eq(createUriWithParameters(
						"grant_type=client_credentials&client_id=clientid&client_secret=mysecretpassword")),
				any(HttpEntity.class), eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));

		Map<String, String> overwrittenGrantType = new HashMap<>();
		overwrittenGrantType.put(OAuth2TokenServiceConstants.GRANT_TYPE, "overwrite-obligatory-param");

		OAuth2AccessToken accessToken = cut.retrieveAccessTokenViaClientCredentialsGrant(tokenEndpoint,
				clientCredentials, null,
				overwrittenGrantType);
		assertThat(accessToken.getValue(), is(responseMap.get(ACCESS_TOKEN)));
	}

	private URI createUriWithParameters(String queryParameterList) {
		return URI.create(tokenEndpoint.toString() + "?" + queryParameterList);
	}
}