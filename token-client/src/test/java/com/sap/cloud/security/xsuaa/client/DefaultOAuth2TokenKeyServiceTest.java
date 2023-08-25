/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class DefaultOAuth2TokenKeyServiceTest {

	public static final URI TOKEN_KEYS_ENDPOINT_URI = URI.create("https://tokenKeys.io/token_keys");
	public static final String APP_TID = "92768714-4c2e-4b79-bc1b-009a4127ee3c";
	public static final String CLIENT_ID = "client-id";
	private final String jsonWebKeysAsString;

	private DefaultOAuth2TokenKeyService cut;
	private CloseableHttpClient httpClient;

	public DefaultOAuth2TokenKeyServiceTest() throws IOException {
		jsonWebKeysAsString = IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Before
	public void setUp() {
		httpClient = Mockito.mock(CloseableHttpClient.class);
		cut = new DefaultOAuth2TokenKeyService(httpClient);
	}

	@Test
	public void httpClient_isNull_throwsException() {
		assertThatThrownBy(() -> new DefaultOAuth2TokenKeyService(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeysForZone_responseNotOk_throwsException() throws IOException {
		String errorDescription = "Something went wrong";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(errorDescription, HttpStatus.SC_BAD_REQUEST);
		when(httpClient.execute(any(), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, APP_TID, CLIENT_ID))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorDescription)
				.hasMessageContaining("Request headers [x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c, x-client_id: client-id, User-Agent: token-client/")
				.hasMessageContaining("'Something went wrong'")
				.hasMessageContaining("Error retrieving token keys")
				.hasMessageContaining("Response Headers [testHeader: testValue]")
				.hasMessageContaining("Http status code 400");
	}

	@Test
	public void retrieveTokenKeys_responseNotOk_throwsException_noAppTid() throws IOException {
		String errorDescription = "Something went wrong";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(errorDescription, HttpStatus.SC_BAD_REQUEST);
		when(httpClient.execute(any(), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		OAuth2ServiceException e = assertThrows(OAuth2ServiceException.class,
				() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, null, CLIENT_ID));

		assertThat(e.getHeaders()).contains("testHeader: testValue");
		assertThat(e.getHttpStatusCode()).isEqualTo(400);
		assertThat(e.getMessage())
				.contains(errorDescription)
				.contains("Request headers [User-Agent: token-client/")
				.contains("Response Headers [testHeader: testValue]")
				.contains("Http status code 400")
				.contains("Server URI https://tokenKeys.io/token_keys");
	}

	@Test
	public void retrieveTokenKeys_responseNotOk_throwsException() throws IOException {
		String errorDescription = "Something went wrong";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(errorDescription, HttpStatus.SC_BAD_REQUEST);
		when(httpClient.execute(any(), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, null, null))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorDescription)
				.hasMessageContaining("'Something went wrong'")
				.hasMessageContaining("Error retrieving token keys");
	}

	@Test
	public void retrieveTokenKeys_tokenEndpointUriIsNull_throwsException() {
		assertThatThrownBy(() -> cut.retrieveTokenKeys(null, APP_TID, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeys_errorOccurs_throwsServiceException() throws IOException {
		String errorMessage = "useful error message";
		when(httpClient.execute(any(), any(ResponseHandler.class))).thenThrow(new IOException(errorMessage));

		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, APP_TID, null))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorMessage);
	}

	@Test
	public void retrieveTokenKeys_executesHttpGetRequestWithCorrectURI() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(jsonWebKeysAsString);

		when(httpClient.execute(any(), any(ResponseHandler.class))).thenAnswer(invocation -> {
			ResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, APP_TID, CLIENT_ID);

		Mockito.verify(httpClient, times(1)).execute(argThat(isHttpGetAndContainsCorrectURI()),
				any(ResponseHandler.class));
	}

	private ArgumentMatcher<HttpUriRequest> isHttpGetAndContainsCorrectURI() {
		return (httpGet) -> {
			boolean hasCorrectURI = httpGet.getURI().equals(TOKEN_KEYS_ENDPOINT_URI);
			boolean correctMethod = httpGet.getMethod().equals(HttpMethod.GET.toString());
			boolean correctTenantHeader = httpGet.getFirstHeader(HttpHeaders.X_APP_TID).getValue().equals(APP_TID);
			boolean correctClientId = httpGet.getFirstHeader(HttpHeaders.X_CLIENT_ID).getValue().equals(CLIENT_ID);
			return hasCorrectURI && correctMethod && correctTenantHeader && correctClientId;
		};
	}
}