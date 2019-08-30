package com.sap.cloud.security.xsuaa.extractor;

import java.util.Base64;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

@Component
public class UaaTokenBroker implements TokenBroker {

	private final static Log logger = LogFactory.getLog(UaaTokenBroker.class);

	private final RestTemplate restTemplate;

	public UaaTokenBroker(RestTemplate restTemplate) {
		super();
		this.restTemplate = restTemplate;
	}

	public UaaTokenBroker() {
		this(new RestTemplate());
	}

	@Override
	@Cacheable(cacheManager = "xsuaa.tokenbroker")
	public String getAccessTokenFromClientCredentials(String tokenURL, String clientId, String clientSecret)
			throws TokenBrokerException {

		try {
			HttpHeaders headers = new HttpHeaders();
			String credentials = clientId + ":" + clientSecret;
			String base64Creds = Base64.getEncoder().encodeToString(credentials.getBytes());
			headers.add("ACCEPT", "application/json");
			headers.add("AUTHORIZATION", "Basic " + base64Creds);

			MultiValueMap<String, String> body = new LinkedMultiValueMap<String, String>();

			body.add("grant_type", "client_credentials");
			body.add("response_type", "token");
			body.add("client_id", clientId);

			// Note the body object as first parameter!
			HttpEntity<?> httpEntity = new HttpEntity<Object>(body, headers);

			@SuppressWarnings("rawtypes")
			ResponseEntity<Map> exchange = restTemplate.exchange(tokenURL, HttpMethod.POST, httpEntity, Map.class);

			return (String) exchange.getBody().get("access_token");
		} catch (HttpClientErrorException ex) {
			logger.warn("Cannot obtain Token from given client credentials");
			throw new TokenBrokerException(
					"Error obtaining access token:" + ex.getStatusText() + " " + ex.getResponseBodyAsString());
		} catch (HttpServerErrorException ex) {
			logger.warn("Cannot obtain Token from given client credentials");
			throw new TokenBrokerException("Error obtaining access token from server:" + ex.getStatusText() + " "
					+ ex.getResponseBodyAsString());
		}
	}

	@Override
	public String getAccessTokenFromPasswordCredentials(String tokenURL, String clientId, String clientSecret,
			String username, String password) throws TokenBrokerException {
		try {
			HttpHeaders headers = new HttpHeaders();
			String credentials = clientId + ":" + clientSecret;
			String base64Creds = Base64.getEncoder().encodeToString(credentials.getBytes());
			headers.add("ACCEPT", "application/json");
			headers.add("AUTHORIZATION", "Basic " + base64Creds);

			MultiValueMap<String, String> body = new LinkedMultiValueMap<String, String>();

			body.add("grant_type", "password");
			body.add("response_type", "token");
			body.add("client_id", clientId);
			body.add("username", username);
			body.add("password", password);

			// Note the body object as first parameter!
			HttpEntity<?> httpEntity = new HttpEntity<Object>(body, headers);

			@SuppressWarnings("rawtypes")
			ResponseEntity<Map> exchange = restTemplate.exchange(tokenURL, HttpMethod.POST, httpEntity, Map.class);

			return (String) exchange.getBody().get("access_token");

		} catch (HttpClientErrorException ex) {
			logger.warn("Cannot obtain Token from given password credentials");
			throw new TokenBrokerException(
					"Error obtaining access token:" + ex.getStatusText() + " " + ex.getResponseBodyAsString());
		} catch (HttpServerErrorException ex) {
			logger.warn("Cannot obtain Token from given password credentials");
			throw new TokenBrokerException("Error obtaining access token from server:" + ex.getStatusText() + " "
					+ ex.getResponseBodyAsString());
		}
	}

}