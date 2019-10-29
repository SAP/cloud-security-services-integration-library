package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKeySetFactory;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKeySet;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.stream.Collectors;

public class DefaultOAuth2TokenKeyService implements OAuth2TokenKeyService {

	private final CloseableHttpClient httpClient;

	public DefaultOAuth2TokenKeyService() {
		httpClient = HttpClients.createDefault();
	}

	public DefaultOAuth2TokenKeyService(CloseableHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public JSONWebKeySet retrieveTokenKeys(URI tokenKeysEndpointUri) throws OAuth2ServiceException {
		Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
		HttpUriRequest request = new HttpGet(tokenKeysEndpointUri);
		try (CloseableHttpResponse response = httpClient.execute(request)) {
			return JSONWebKeySetFactory.createFromJSON(convertToString(response));
		} catch (IOException e) {
			throw new OAuth2ServiceException(e.getMessage());
		}
	}

	private String convertToString(HttpResponse response) throws IOException {
		return new BufferedReader(new InputStreamReader(response.getEntity().getContent()))
				.lines().collect(Collectors.joining(System.lineSeparator()));
	}
}
