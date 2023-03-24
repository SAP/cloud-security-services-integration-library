/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class DefaultOAuth2TokenKeyServiceTest {

	public static final URI TOKEN_KEYS_ENDPOINT_URI = URI.create("https://tokenKeys.io/token_keys");
	public static final String ZONE_UUID = "92768714-4c2e-4b79-bc1b-009a4127ee3c";
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
		when(httpClient.execute(any(), any(HttpClientResponseHandler.class))).thenAnswer(invocation -> {
			HttpClientResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, ZONE_UUID))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorDescription)
				.hasMessageContaining("'Something went wrong'")
				.hasMessageContaining("Error retrieving token keys")
				.hasMessageContaining("Headers [x-zone_uuid=92768714-4c2e-4b79-bc1b-009a4127ee3c]");
	}

	@Test
	public void retrieveTokenKeys_responseNotOk_throwsException() throws IOException {
		String errorDescription = "Something went wrong";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(errorDescription, HttpStatus.SC_BAD_REQUEST);
		when(httpClient.execute(any(), any(HttpClientResponseHandler.class))).thenAnswer(invocation -> {
			HttpClientResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, null))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorDescription)
				.hasMessageContaining("'Something went wrong'")
				.hasMessageContaining("Error retrieving token keys");
	}

	@Test
	public void retrieveTokenKeys_tokenEndpointUriIsNull_throwsException() {
		assertThatThrownBy(() -> cut.retrieveTokenKeys(null, ZONE_UUID))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeys_errorOccurs_throwsServiceException() throws IOException {
		String errorMessage = "useful error message";
		when(httpClient.execute(any(), any(HttpClientResponseHandler.class))).thenThrow(new IOException(errorMessage));

		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, ZONE_UUID))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorMessage);
	}

	@Test
	public void retrieveTokenKeys_executesHttpGetRequestWithCorrectURI() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(jsonWebKeysAsString);

		when(httpClient.execute(any(), any(HttpClientResponseHandler.class))).thenAnswer(invocation -> {
			HttpClientResponseHandler responseHandler = invocation.getArgument(1);
			return responseHandler.handleResponse(response);
		});

		cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, ZONE_UUID);

		Mockito.verify(httpClient, times(1)).execute(argThat(isHttpGetAndContainsCorrectURI()), any(HttpClientResponseHandler.class));
	}

	private ArgumentMatcher<HttpUriRequest> isHttpGetAndContainsCorrectURI() {
		return (httpGet) -> {
			boolean hasCorrectURI = false;
			try {
				hasCorrectURI = httpGet.getUri().equals(TOKEN_KEYS_ENDPOINT_URI);
			} catch (URISyntaxException e) {}
			boolean correctMethod = httpGet.getMethod().equals(HttpMethod.GET.toString());
			boolean correctZoneHeader = httpGet.getFirstHeader(HttpHeaders.X_ZONE_UUID).getValue().equals(ZONE_UUID);
			return hasCorrectURI && correctMethod && correctZoneHeader;
		};
	}
}