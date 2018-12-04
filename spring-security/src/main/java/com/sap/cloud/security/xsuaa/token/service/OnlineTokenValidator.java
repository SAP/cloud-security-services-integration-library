package com.sap.cloud.security.xsuaa.token.service;

import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.ServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.jwt.UaaTokenUtils;
import com.sap.cloud.security.xsuaa.token.service.exceptions.TokenValidationException;

public class OnlineTokenValidator extends AbstractTokenValidator {

	private final RestTemplate restTemplate;

	private static final String CHECK_TOKEN = "/check_token";
	private ServiceConfiguration configuration;

	public OnlineTokenValidator(ServiceConfiguration configuration, RestTemplate restTemplate) {
		super(configuration);
		this.configuration = configuration;
		this.restTemplate = restTemplate;
	}

	@Override
	protected Map<String, Object> checkToken(String tokenValue, String clientId, String clientSecret) throws TokenValidationException {
		logger.debug("Try online validation of access token");

		if (UaaTokenUtils.isJwtToken(tokenValue) && isPlatformToken(tokenValue)) {
			// cf-uaa token
			String checkTokenEndpointUrl = getEndpoint(configuration.getPlatformUrl(), UaaTokenUtils.PLATFORM_SUB_URL_1, tokenValue, CHECK_TOKEN);
			return obtainAuthentication(tokenValue, checkTokenEndpointUrl, configuration.getPlatformClientId(), configuration.getPlatformClientSecret());
		} else {
			// xsuaa token
			String checkTokenEndpointUrl = getEndpoint(configuration.getUaaUrl(), configuration.getUaadomain(), tokenValue, CHECK_TOKEN);
			return obtainAuthentication(tokenValue, checkTokenEndpointUrl, configuration.getClientId(), configuration.getClientSecret());
		}
	}

	private Map<String, Object> obtainAuthentication(String accessToken, String checkTokenEndpointUrl, String clientId, String clientSecret) {
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("token", accessToken);
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", getAuthorizationHeader(clientId, clientSecret));
		Map<String, Object> tokenInfo = postForMap(checkTokenEndpointUrl, formData, headers);
		return tokenInfo;
	}

	/**
	 * Queries the endpoint to obtain the contents of an access token.
	 *
	 * If the endpoint returns a 400 response, this indicates that the token is invalid.
	 * 
	 * @param path
	 *            Endpoint-URL
	 * @param formData
	 *            Payload
	 * @param headers
	 *            Request Header
	 * @return Response
	 */
	@SuppressWarnings("rawtypes")
	protected Map<String, Object> postForMap(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
		if (headers.getContentType() == null) {
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		}

		ResponseEntity<Map> exchange;
		try {
			exchange = restTemplate.exchange(path, HttpMethod.POST, new HttpEntity<MultiValueMap<String, String>>(formData, headers), Map.class);
		} catch (RestClientException e) {
			String errorMsg = "Cannot check token against UAA";
			logger.error(errorMsg, e);
			throw new TokenValidationException(errorMsg, e);
		}

		Map map = exchange.getBody();
		@SuppressWarnings("unchecked")
		Map<String, Object> result = map;
		return result;
	}

	@Override
	public boolean isApplicable(String tokenValue) {
		return true;
	}

}
