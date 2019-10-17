package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import com.sap.cloud.security.xsuaa.util.UriUtil;

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
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nullable;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

public class XsuaaOAuth2TokenService extends AbstractOAuth2TokenService {

	private final RestOperations restOperations;
	private static Logger logger = LoggerFactory.getLogger(XsuaaOAuth2TokenService.class);
	private final HttpHeadersFactory httpHeadersFactory;

	public XsuaaOAuth2TokenService(@Nonnull RestOperations restOperations) {
		assertNotNull(restOperations, "restOperations is required");
		this.restOperations = restOperations;
		this.httpHeadersFactory = new HttpHeadersFactory();
	}

	/**
	 * @param tokenEndpointUri
	 * @param clientCredentials
	 *            contains id of master (extracted from VCAP_SERVICES system
	 *            environment variable)
	 * @param oidcToken
	 * @param pemEncodedCloneCertificate
	 * @param subdomain
	 * @param optionalParameters
	 * @return
	 * @throws OAuth2ServiceException
	 */
	@Nullable
	public OAuth2TokenResponse retrieveDelegationAccessTokenViaJwtBearerTokenGrant(URI tokenEndpointUri,
			ClientCredentials clientCredentials, String oidcToken, String pemEncodedCloneCertificate,
			@Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters) throws OAuth2ServiceException {
		assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		assertNotNull(clientCredentials.getId(), "client ID is required (master)");
		assertHasText(oidcToken, "oidcToken is required");
		assertHasText(pemEncodedCloneCertificate, "pemEncodedCertificate is required (clone)"); // w/o BEGIN CERTIFICATE ...

		if (!testCertificate()) {
			return null;
		}

		HashMap optionalParams = new HashMap();
		optionalParams.put("assertion", oidcToken);
		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_JWT_BEARER) // default "client_x509"
				.withCertificate(clientCredentials.getId(), pemEncodedCloneCertificate)
				.withOptionalParameters(optionalParams)
				.buildAsMap();

		HttpHeaders headers = httpHeadersFactory.createWithoutAuthorizationHeader();
		//HttpHeaders headers = httpHeadersFactory.createWithAuthorizationBearerHeader(oidcToken);

		return requestAccessToken(UriUtil.replaceSubdomain(tokenEndpointUri, subdomain), headers, parameters);
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
		ResponseEntity<Map> responseEntity = null;
		try {
			responseEntity = restOperations.postForEntity(requestUri, requestEntity, Map.class);
		} catch (HttpClientErrorException ex) {
			String warningMsg = String.format(
					"Error retrieving JWT token. Received status code %s. Call to XSUAA was not successful: %s",
					ex.getStatusCode(), ex.getResponseBodyAsString());
			throw new OAuth2ServiceException(warningMsg);
		} catch (HttpServerErrorException ex) {
			String warningMsg = String.format("Server error while obtaining access token from XSUAA (%s): %s",
					ex.getStatusCode(), ex.getResponseBodyAsString());
			logger.error(warningMsg, ex);
			throw new OAuth2ServiceException(warningMsg);
		}

		@SuppressWarnings("unchecked")
		Map<String, String> accessTokenMap = responseEntity.getBody();
		logger.debug("Request Access Token: {}", responseEntity.getBody());

		String accessToken = accessTokenMap.get(ACCESS_TOKEN);
		long expiresIn = Long.parseLong(String.valueOf(accessTokenMap.get(EXPIRES_IN)));
		String refreshToken = accessTokenMap.get(REFRESH_TOKEN);
		return new OAuth2TokenResponse(accessToken, expiresIn, refreshToken);
	}

	private boolean testCertificate()
			throws OAuth2ServiceException {
		// TODO is it possible to check whether restOperation has SSLContext
		// TODO "authentication" domain -> "authentication.cert"
		// TODO delegation
		URI uri = URI.create("https://d047491-show-headers.cert.cfapps.sap.hana.ondemand.com");
		ResponseEntity<String> payload = restOperations.getForEntity(uri, String.class);

		return payload.getBody().contains("x-forwarded-client-cert");
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
