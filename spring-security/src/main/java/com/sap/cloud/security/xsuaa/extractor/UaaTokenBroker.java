package com.sap.cloud.security.xsuaa.extractor;

import java.util.Base64;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.extractor.intern.LoggerInterceptor;
import com.sap.cloud.security.xsuaa.token.service.TokenBrokerException;

public class UaaTokenBroker implements TokenBroker {

	private final static Log logger = LogFactory.getLog(UaaTokenBroker.class);
	private static List<ClientHttpRequestInterceptor> LOGGING_INTERCEPTOR = LoggerInterceptor.getInterceptor(logger);

	private final RestTemplate restTemplate;

	public UaaTokenBroker(RestTemplate restTemplate) {
		super();
		this.restTemplate = restTemplate;
		this.restTemplate.setInterceptors(LOGGING_INTERCEPTOR);
	}

	@Override
	public DefaultOAuth2AccessToken getAccessTokenFromClientCredentials(String tokenURL, String clientId, String clientSecret) throws TokenBrokerException {

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
			ResponseEntity<DefaultOAuth2AccessToken> exchange = restTemplate.exchange(tokenURL, HttpMethod.POST, httpEntity, DefaultOAuth2AccessToken.class);

			return exchange.getBody();
		} catch (Exception ex) {
			logger.warn("Cannot obtain Token from given client credentials");
			throw new TokenBrokerException("Error obtaining access token", ex);
		}
	}

	@Override
	public DefaultOAuth2AccessToken getAccessTokenFromPasswordCredentials(String tokenURL, String clientId, String clientSecret, String username, String password) throws TokenBrokerException {
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
			ResponseEntity<DefaultOAuth2AccessToken> exchange = restTemplate.exchange(tokenURL, HttpMethod.POST, httpEntity, DefaultOAuth2AccessToken.class);

			return exchange.getBody();
			
		} catch (Exception ex) {
			logger.warn("Cannot obtain Token from given password credentials");
			throw new TokenBrokerException("Error obtaining access token", ex);
		}
	}

}