/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.servlet.MDCHelper;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.Nonnull;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

/**
 * Implementation for Spring applications, that uses {@link RestOperations}.
 */
public class XsuaaOAuth2TokenService extends AbstractOAuth2TokenService {

	private static final Logger LOGGER = LoggerFactory.getLogger(XsuaaOAuth2TokenService.class);
	private final RestOperations restOperations;

	public XsuaaOAuth2TokenService(@Nonnull RestOperations restOperations) {
		this(restOperations, TokenCacheConfiguration.defaultConfiguration());
	}

	public XsuaaOAuth2TokenService(@Nonnull RestOperations restOperations,
			@Nonnull TokenCacheConfiguration tokenCacheConfiguration) {
		super(tokenCacheConfiguration);
		assertNotNull(restOperations, "restOperations is required");
		this.restOperations = restOperations;
	}

	@Override
	protected OAuth2TokenResponse requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
			Map<String, String> parameters) throws OAuth2ServiceException {

		// Create URI
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenEndpointUri);
		URI requestUri = builder.build().encode().toUri();
		org.springframework.http.HttpHeaders springHeaders = new org.springframework.http.HttpHeaders();
		headers.getHeaders().forEach(h -> springHeaders.add(h.getName(), h.getValue()));
		springHeaders.add(MDCHelper.CORRELATION_HEADER, MDCHelper.getOrCreateCorrelationId());
		springHeaders.add(org.springframework.http.HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());
		// Create entity
		HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(copyIntoForm(parameters),
				springHeaders);
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> responseEntity;
		try {
			LOGGER.debug("Requesting access token from url='{}' and headers={}", requestUri, springHeaders);
			responseEntity = restOperations.postForEntity(requestUri, requestEntity, Map.class);
		} catch (HttpClientErrorException ex) {
			String warningMsg = String.format(
					"Error retrieving JWT token. Received status code %s. Call to XSUAA was not successful: %s",
					ex.getStatusCode(), ex.getResponseBodyAsString());
			throw new OAuth2ServiceException(warningMsg, ex.getStatusCode().value(),
					getHeaders(ex.getResponseHeaders()));
		} catch (HttpServerErrorException ex) {
			String warningMsg = String.format("Server error while obtaining access token from XSUAA (%s): %s",
					ex.getStatusCode(), ex.getResponseBodyAsString());
			LOGGER.error(warningMsg, ex);
			throw new OAuth2ServiceException(warningMsg, ex.getStatusCode().value(),
					getHeaders(ex.getResponseHeaders()));
		} catch (ResourceAccessException ex) {
			String warningMsg = String.format(
					"RestClient isn't configured properly - Error while obtaining access token from XSUAA (%s): %s",
					requestUri, ex.getLocalizedMessage());
			LOGGER.error(warningMsg);
			throw ex;
		}
		LOGGER.debug("Received statusCode {}", responseEntity.getStatusCode());

		@SuppressWarnings("unchecked")
		Map<String, String> accessTokenMap = responseEntity.getBody();

		String accessToken = accessTokenMap.get(ACCESS_TOKEN);
		long expiresIn = Long.parseLong(String.valueOf(accessTokenMap.get(EXPIRES_IN)));
		String refreshToken = accessTokenMap.get(REFRESH_TOKEN);
		String tokenType = accessTokenMap.get(TOKEN_TYPE);
		return new OAuth2TokenResponse(accessToken, expiresIn, refreshToken, tokenType);
	}

	private static List<String> getHeaders(org.springframework.http.HttpHeaders ex) {
		if (ex != null) {
			return ex.toSingleValueMap().entrySet().stream().map(e -> e.getKey() + "=" + e.getValue()).toList();
		}
		return Collections.emptyList();
	}

	/**
	 * Creates a copy of the given map or a new empty map of type MultiValueMap.
	 *
	 * @return a new @link{MultiValueMap} that contains all entries of the optional
	 *         map.
	 */
	private MultiValueMap<String, String> copyIntoForm(Map<String, String> parameters) {
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
		if (parameters != null) {
			parameters.forEach(formData::add);
		}
		return formData;
	}

}
