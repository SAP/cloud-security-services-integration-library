/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.xsuaa.client.OidcConfigurationService.DISCOVERY_ENDPOINT_DEFAULT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class DefaultOidcConfigurationServiceTest {
	public static final URI CONFIG_ENDPOINT_URI = URI.create("https://sub.myauth.com" + DISCOVERY_ENDPOINT_DEFAULT);

	private final String jsonOidcConfiguration;

	private CloseableHttpClient httpClientMock;
	private DefaultOidcConfigurationService cut;

	public DefaultOidcConfigurationServiceTest() throws IOException {
		jsonOidcConfiguration = IOUtils.resourceToString("/oidcConfiguration.json", StandardCharsets.UTF_8);
	}

	@Before
	public void setUp() {
		httpClientMock = Mockito.mock(CloseableHttpClient.class);
		cut = new DefaultOidcConfigurationService(httpClientMock);
	}

	@Test
	public void httpClient_isNull_throwsException() {
		assertThatThrownBy(() -> new DefaultOidcConfigurationService(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void retrieveEndpoints_parameterIsNull_throwsException() {
		assertThatThrownBy(() -> cut.retrieveEndpoints(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	@Ignore
	public void retrieveEndpoints_badRequest_throwsException() throws IOException {
		String errorDescription = "Something went wrong";
		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(errorDescription, HttpStatus.SC_BAD_REQUEST);
		when(httpClientMock.execute(any())).thenReturn(response);

		assertThatThrownBy(() -> retrieveEndpoints())
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorDescription);
	}

	@Test
	@Ignore
	public void retrieveEndpoints_executesHttpGetRequestWithCorrectURI() throws IOException {
		mockResponse();

		retrieveEndpoints();

		Mockito.verify(httpClientMock, times(1)).execute(argThat(isHttpGetAndContainsCorrectURI()));

	}

	@Test
	@Ignore
	public void retrieveEndpoints_errorOccurs_throwsServiceException() throws IOException {
		String errorMessage = "useful error message";
		when(httpClientMock.execute(any())).thenThrow(new IOException(errorMessage));

		assertThatThrownBy(() -> retrieveEndpoints())
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining(errorMessage)
				.extracting("httpStatusCode").isEqualTo(0);
	}

	@Test
	public void retrieveIssuerEndpoints_executesHttpGetRequestWithCorrectURI() throws IOException {
		URI discoveryEndpoint1 = DefaultOidcConfigurationService
				.getDiscoveryEndpointUri("https://sub.myauth.com");
		URI discoveryEndpoint2 = DefaultOidcConfigurationService
				.getDiscoveryEndpointUri("https://sub.myauth.com/");
		URI discoveryEndpoint3 = DefaultOidcConfigurationService
				.getDiscoveryEndpointUri("https://sub.myauth.com/path");
		URI discoveryEndpoint4 = DefaultOidcConfigurationService
				.getDiscoveryEndpointUri("https://sub.myauth.com//path");
		URI discoveryEndpoint5 = DefaultOidcConfigurationService
				.getDiscoveryEndpointUri("sub.myauth.com/path");

		assertThat(discoveryEndpoint1.toString()).isEqualTo("https://sub.myauth.com/.well-known/openid-configuration");
		assertThat(discoveryEndpoint2.toString()).isEqualTo("https://sub.myauth.com/.well-known/openid-configuration");
		assertThat(discoveryEndpoint3.toString())
				.isEqualTo("https://sub.myauth.com/path/.well-known/openid-configuration");
		assertThat(discoveryEndpoint4.toString())
				.isEqualTo("https://sub.myauth.com/path/.well-known/openid-configuration");
		assertThat(discoveryEndpoint5.toString())
				.isEqualTo("https://sub.myauth.com/path/.well-known/openid-configuration");
	}

	@Test
	@Ignore
	public void retrieveEndpoints_containsBothKeys() throws IOException {
		mockResponse();

		OAuth2ServiceEndpointsProvider result = retrieveEndpoints();

		assertThat(result.getTokenEndpoint().toString()).isEqualTo("http://localhost/oauth/token");
		assertThat(result.getJwksUri().toString()).isEqualTo("http://localhost/token_keys");
		assertThat(result.getAuthorizeEndpoint().toString()).isEqualTo("http://localhost/oauth/authorize");
	}

	private CloseableHttpResponse mockResponse() throws IOException {
		CloseableHttpResponse response = HttpClientTestFactory.createHttpResponse(jsonOidcConfiguration);
		when(httpClientMock.execute(any())).thenReturn(response);
		return response;
	}

	private OAuth2ServiceEndpointsProvider retrieveEndpoints() throws OAuth2ServiceException {
		return cut.retrieveEndpoints(CONFIG_ENDPOINT_URI);
	}

	private ArgumentMatcher<HttpUriRequest> isHttpGetAndContainsCorrectURI() {
		return (httpGet) -> {
			boolean hasCorrectURI;
			try {
				hasCorrectURI = httpGet.getUri().equals(CONFIG_ENDPOINT_URI);
			} catch (URISyntaxException e) {
				hasCorrectURI = false;
			}
			boolean correctMethod = httpGet.getMethod().equals(HttpMethod.GET.toString());
			return hasCorrectURI && correctMethod;
		};
	}
}