package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.jwt.JsonWebKey;
import com.sap.cloud.security.xsuaa.jwt.JsonWebKeySet;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestOperations;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class SpringOAuth2TokenKeyServiceTest {

	public static final URI TOKEN_KEYS_ENDPOINT_URI = URI.create("https://token.endpoint.io/token_keys");
	private RestOperations restOperationsMock;
	private SpringOAuth2TokenKeyService cut;

	private final String jsonWebKeysAsString;

	public SpringOAuth2TokenKeyServiceTest() throws IOException {
		jsonWebKeysAsString = IOUtils.resourceToString("/JSONWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Before
	public void setUp() throws Exception {
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
		assertThatThrownBy(() -> retrieveTokenKeys(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeys_usesGivenURI() throws OAuth2ServiceException {
		mockResponse();

		retrieveTokenKeys();

		Mockito.verify(restOperationsMock, times(1))
				.getForEntity(TOKEN_KEYS_ENDPOINT_URI, String.class);
	}

	@Test
	public void retrieveTokenKeys_badResponse_throwsException() {
		String errorMessage = "useful error message";
		mockResponse(errorMessage, HttpStatus.BAD_REQUEST);
		assertThatThrownBy(() -> retrieveTokenKeys())
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorMessage);
	}

	@Test
	public void retrieveTokenKeys_containsBothKeys() throws OAuth2ServiceException {
		mockResponse();

		JsonWebKeySet response = retrieveTokenKeys();

		assertThat(response.isEmpty()).isFalse();
		assertThat(response.containsKeyByTypeAndId(JsonWebKey.Type.RSA, "key-id-0")).isTrue();
		assertThat(response.containsKeyByTypeAndId(JsonWebKey.Type.RSA, "key-id-1")).isTrue();
	}

	private void mockResponse() {
		mockResponse(jsonWebKeysAsString, HttpStatus.OK);
	}

	private void mockResponse(String responseAsString, HttpStatus httpStatus) {
		ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(responseAsString, httpStatus);
		when(restOperationsMock.getForEntity(any(URI.class), eq(String.class)))
				.thenReturn(stringResponseEntity);
	}

	private JsonWebKeySet retrieveTokenKeys() throws OAuth2ServiceException {
		return retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI);
	}

	private JsonWebKeySet retrieveTokenKeys(URI tokenKeysEndpointUri) throws OAuth2ServiceException {
		return cut.retrieveTokenKeys(tokenKeysEndpointUri);
	}
}