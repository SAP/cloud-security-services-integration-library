/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestOperations;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpMethod.GET;

public class SpringOAuth2TokenKeyServiceTest {

	public static final URI TOKEN_KEYS_ENDPOINT_URI = URI.create("https://token.endpoint.io/token_keys");
	public static final String ZONE_UUID = "92768714-4c2e-4b79-bc1b-009a4127ee3c";
	private RestOperations restOperationsMock;
	private SpringOAuth2TokenKeyService cut;

	private final String jsonWebKeysAsString;

	public SpringOAuth2TokenKeyServiceTest() throws IOException {
		jsonWebKeysAsString = IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Before
	public void setUp() {
		restOperationsMock = mock(RestOperations.class);
		cut = new SpringOAuth2TokenKeyService(restOperationsMock);
	}

	@Test
	public void restOperations_isNull_throwsException() {
		assertThatThrownBy(() -> new SpringOAuth2TokenKeyService(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeys_endpointUriIsNull_throwsException() throws OAuth2ServiceException {
		assertThatThrownBy(() -> cut.retrieveTokenKeys(null, ZONE_UUID))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeys_usesGivenURI() throws OAuth2ServiceException {
		mockResponse();

		cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, ZONE_UUID);

		Mockito.verify(restOperationsMock, times(1))
				.exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), argThat(httpEntityContainsZoneIdHeader()),
						eq(String.class));
	}

	@Test
	public void retrieveTokenKeys_badResponse_throwsException() {
		String errorMessage = "useful error message";
		mockResponse(errorMessage, HttpStatus.BAD_REQUEST);
		assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, ZONE_UUID))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
				.hasMessageContaining(String.valueOf(HttpStatus.BAD_REQUEST.value()))
				.hasMessageContaining(errorMessage);
	}

	private void mockResponse() {
		mockResponse(jsonWebKeysAsString, HttpStatus.OK);
	}

	private void mockResponse(String responseAsString, HttpStatus httpStatus) {
		ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(responseAsString, httpStatus);
		when(restOperationsMock.exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(HttpEntity.class), eq(String.class)))
				.thenReturn(stringResponseEntity);
	}

	private ArgumentMatcher<HttpEntity> httpEntityContainsZoneIdHeader() {
		return (httpGet) -> httpGet.getHeaders().getFirst(HttpHeaders.X_ZONE_UUID).equals(ZONE_UUID);
	}

}