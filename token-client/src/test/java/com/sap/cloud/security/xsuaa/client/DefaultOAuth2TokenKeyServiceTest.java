package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.jwt.JSONWebKey;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKeySet;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class DefaultOAuth2TokenKeyServiceTest {

	private final String jsonWebKeysAsString;

	private DefaultOAuth2TokenKeyService cut;
	private CloseableHttpClient httpClient;

	public DefaultOAuth2TokenKeyServiceTest() throws IOException {
		jsonWebKeysAsString = IOUtils.resourceToString("/JSONWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Before
	public void setUp() {
		httpClient = Mockito.mock(CloseableHttpClient.class);
		cut = new DefaultOAuth2TokenKeyService(httpClient);
	}

	@Test
	public void retrieveTokenKeys_tokenEndpointUriIsNull_throwsException()  {
		assertThatThrownBy(() -> retrieveTokenKeys(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveTokenKeys_executesHttpGetRequest() throws IOException {
		mockResponse();

		retrieveTokenKeys();

		Mockito.verify(httpClient, times(1)).execute(any(HttpGet.class));
	}
	
	@Test
	public void retrieveTokenKeys_keySetAsResponse_containsBothKeys() throws IOException {
		mockResponse();

		JSONWebKeySet result = retrieveTokenKeys();

		assertThat(result.containsKeyByTypeAndId(JSONWebKey.Type.RSA, "key-id-0")).isTrue();
		assertThat(result.containsKeyByTypeAndId(JSONWebKey.Type.RSA, "key-id-1")).isTrue();
	}

	@Test
	public void retrieveTokenKeys_errorOccurs_throwsServiceException() throws IOException {
		String errorMessage = "useful error message";
		when(httpClient.execute(any())).thenThrow(new IOException(errorMessage));

		assertThatThrownBy(() -> retrieveTokenKeys())
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorMessage);
	}

	private void mockResponse() throws IOException {
		CloseableHttpResponse webKeys = HttpClientTestFactory.createHttpResponse(jsonWebKeysAsString);
		when(httpClient.execute(any())).thenReturn(webKeys);
	}

	private JSONWebKeySet retrieveTokenKeys() throws OAuth2ServiceException {
		return retrieveTokenKeys(URI.create("https://tokenKeys.io/token_keys"));
	}

	private JSONWebKeySet retrieveTokenKeys(URI uri) throws OAuth2ServiceException {
		return cut.retrieveTokenKeys(uri);
	}
}