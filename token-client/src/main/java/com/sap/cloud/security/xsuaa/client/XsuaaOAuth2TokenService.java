/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.mtls.ServiceClientException;
import com.sap.cloud.security.xsuaa.mtls.SpringHttpClient;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import com.sap.xsa.security.container.ClientIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.Nonnull;
import java.net.URI;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

/**
 *
 */
public class XsuaaOAuth2TokenService extends AbstractOAuth2TokenService {

	private static final Logger LOGGER = LoggerFactory.getLogger(XsuaaOAuth2TokenService.class);
	private RestOperations restOperations;

	public XsuaaOAuth2TokenService() {
		this(SpringHttpClient.create(), TokenCacheConfiguration.defaultConfiguration());
	}

	public XsuaaOAuth2TokenService(@Nonnull TokenCacheConfiguration tokenCacheConfiguration) {
		this(SpringHttpClient.create(), tokenCacheConfiguration); // TODO check for occurrences of new RestTemplate() and
																	// httpsclient for appache
	}

	public XsuaaOAuth2TokenService(@Nonnull RestOperations restOperations) {
		this(restOperations, TokenCacheConfiguration.defaultConfiguration());
	}

	public XsuaaOAuth2TokenService(@Nonnull RestOperations restOperations,
			@Nonnull TokenCacheConfiguration tokenCacheConfiguration) {
		super(tokenCacheConfiguration);
		assertNotNull(restOperations, "restOperations is required");
		this.restOperations = restOperations;
	}

	/**
	 * Convenience method to create OAuth2TokenService with certificate based communication
	 * @param clientCertificate Client Identity of Xsuaa instance
	 * @return OAuth2TokenService
	 * @throws ServiceClientException in case HTTPS client could not be created
	 */
	public OAuth2TokenService enableMtls(ClientIdentity clientCertificate) throws ServiceClientException {
		assertNotNull(clientCertificate, "clientCertificate is required");
		this.restOperations = SpringHttpClient.create(clientCertificate);
		return this;
	}

	@Override
	protected OAuth2TokenResponse requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
			Map<String, String> parameters) throws OAuth2ServiceException {

		// Create URI
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenEndpointUri);
		URI requestUri = builder.build().encode().toUri();

		org.springframework.http.HttpHeaders springHeaders = new org.springframework.http.HttpHeaders();
		headers.getHeaders().forEach(h -> springHeaders.add(h.getName(), h.getValue()));

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
			throw new OAuth2ServiceException(warningMsg);
		} catch (HttpServerErrorException ex) {
			String warningMsg = String.format("Server error while obtaining access token from XSUAA (%s): %s",
					ex.getStatusCode(), ex.getResponseBodyAsString());
			LOGGER.error(warningMsg, ex);
			throw new OAuth2ServiceException(warningMsg);
		}
		LOGGER.debug("Received statusCode {}", responseEntity.getStatusCode());

		@SuppressWarnings("unchecked")
		Map<String, String> accessTokenMap = responseEntity.getBody();

		String accessToken = accessTokenMap.get(ACCESS_TOKEN);
		long expiresIn = Long.parseLong(String.valueOf(accessTokenMap.get(EXPIRES_IN)));
		String refreshToken = accessTokenMap.get(REFRESH_TOKEN);
		return new OAuth2TokenResponse(accessToken, expiresIn, refreshToken);
	}

	/**
	 * Creates a copy of the given map or an new empty map of type MultiValueMap.
	 *
	 * @return a new @link{MultiValueMap} that contains all entries of the optional
	 *         map.
	 */
	private MultiValueMap<String, String> copyIntoForm(Map<String, String> parameters) {
		MultiValueMap<String, String> formData = new LinkedMultiValueMap();
		if (parameters != null) {
			parameters.forEach(formData::add);
		}
		return formData;
	}

}
