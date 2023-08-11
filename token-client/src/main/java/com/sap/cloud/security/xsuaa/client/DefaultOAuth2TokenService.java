/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.servlet.MDCHelper;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static org.apache.http.HttpHeaders.USER_AGENT;

public class DefaultOAuth2TokenService extends AbstractOAuth2TokenService {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultOAuth2TokenService.class);

	private final CloseableHttpClient httpClient;

	public DefaultOAuth2TokenService(@Nonnull CloseableHttpClient httpClient) {
		this(httpClient, TokenCacheConfiguration.defaultConfiguration());
	}

	public DefaultOAuth2TokenService(@Nonnull CloseableHttpClient httpClient,
			@Nonnull TokenCacheConfiguration tokenCacheConfiguration) {
		super(tokenCacheConfiguration);
		Assertions.assertNotNull(httpClient, "http client is required");
		this.httpClient = httpClient;
	}

	@Override
	protected OAuth2TokenResponse requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
			Map<String, String> parameters) throws OAuth2ServiceException {
		HttpHeaders requestHeaders = new HttpHeaders();
		headers.getHeaders().forEach(h -> requestHeaders.withHeader(h.getName(), h.getValue()));
		requestHeaders.withHeader(MDCHelper.CORRELATION_HEADER, MDCHelper.getOrCreateCorrelationId());

		HttpPost httpPost = createHttpPost(tokenEndpointUri, requestHeaders, parameters);
		LOGGER.debug("access token request {} - {}", headers, parameters.entrySet().stream()
				.map(e -> {
					if (e.getKey().contains(PASSWORD) || e.getKey().contains(CLIENT_SECRET)
							|| e.getKey().contains(ASSERTION)) {
						return new AbstractMap.SimpleImmutableEntry<>(e.getKey(), "****");
					}
					return e;
				})
				.toList());

		try {
			return executeRequest(httpPost);
		} catch (IOException | URISyntaxException e) {
			if (e instanceof OAuth2ServiceException oAuth2Exception)
				throw oAuth2Exception;
			throw new OAuth2ServiceException("Unexpected error retrieving JWT token: " + e.getMessage());
		}
	}

	private OAuth2TokenResponse executeRequest(HttpPost httpPost) throws IOException, URISyntaxException {
		httpPost.addHeader(USER_AGENT, HttpClientUtil.getUserAgent());

		URI requestUri = httpPost.getURI();
		LOGGER.debug("Requesting access token from url {} with headers {}", requestUri,
				httpPost.getAllHeaders());

		String responseBody = httpClient.execute(httpPost, response -> {
			int statusCode = response.getStatusLine().getStatusCode();
			LOGGER.debug("Received statusCode {}", statusCode);
			String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

			if (statusCode != HttpStatus.SC_OK) {
				LOGGER.debug("Received response body: {}", body);
				throw OAuth2ServiceException.builder("Error retrieving JWT token")
						.withStatusCode(statusCode)
						.withUri(requestUri)
						.withHeaders(Arrays.toString(response.getAllHeaders()))
						.withResponseBody(body)
						.build();
			}

			return body;
		});

		return convertToOAuth2TokenResponse(responseBody);
	}

	private OAuth2TokenResponse convertToOAuth2TokenResponse(String responseBody)
			throws OAuth2ServiceException {
		Map<String, Object> accessTokenMap = new JSONObject(responseBody).toMap();
		String accessToken = getParameter(accessTokenMap, ACCESS_TOKEN);
		String refreshToken = getParameter(accessTokenMap, REFRESH_TOKEN);
		String expiresIn = getParameter(accessTokenMap, EXPIRES_IN);
		String tokenType = getParameter(accessTokenMap, TOKEN_TYPE);
		return new OAuth2TokenResponse(accessToken, convertExpiresInToLong(expiresIn),
				refreshToken, tokenType);
	}

	private Long convertExpiresInToLong(String expiresIn) throws OAuth2ServiceException {
		try {
			return Long.parseLong(expiresIn);
		} catch (NumberFormatException e) {
			throw new OAuth2ServiceException(
					String.format("Cannot convert expires_in from response (%s) to long", expiresIn));
		}
	}

	private String getParameter(Map<String, Object> accessTokenMap, String key) {
		return String.valueOf(accessTokenMap.get(key));
	}

	private HttpPost createHttpPost(URI uri, HttpHeaders headers, Map<String, String> parameters)
			throws OAuth2ServiceException {
		HttpPost httpPost = new HttpPost(uri);
		headers.getHeaders().forEach(header -> httpPost.setHeader(header.getName(), header.getValue()));
		List<BasicNameValuePair> basicNameValuePairs = parameters.entrySet().stream()
				.map(entry -> new BasicNameValuePair(entry.getKey(), entry.getValue()))
				.toList();
		try {
			httpPost.setEntity(new UrlEncodedFormEntity(basicNameValuePairs));
		} catch (UnsupportedEncodingException e) {
			throw new OAuth2ServiceException("Unexpected error parsing URI: " + e.getMessage());
		}
		return httpPost;
	}

}
