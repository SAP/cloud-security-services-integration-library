package com.sap.cloud.security.xsuaa.extractor;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;

/**
 * @deprecated in favor of {@link #UaaTokenBroker(OAuth2TokenService)}. We are
 *             going to delete that in 3.0.0.
 */
class UaaTokenBroker implements TokenBroker {

	private final static Logger logger = LoggerFactory.getLogger(UaaTokenBroker.class);

	private final RestTemplate restTemplate;
	private OAuth2TokenService oAuth2TokenService;

	public UaaTokenBroker(RestTemplate restTemplate) {
		this.restTemplate = restTemplate;
		this.oAuth2TokenService = new XsuaaOAuth2TokenService(restTemplate);
	}

	public UaaTokenBroker() {
		this(new RestTemplate());
	}

	UaaTokenBroker(OAuth2TokenService tokenService) {
		this.restTemplate = new RestTemplate();
		oAuth2TokenService = tokenService;
	}

	@Override
	public String getAccessTokenFromClientCredentials(String tokenURL, String clientId, String clientSecret)
			throws TokenBrokerException {
		try {
			return oAuth2TokenService.retrieveAccessTokenViaClientCredentialsGrant(
					URI.create(tokenURL), new ClientCredentials(clientId, clientSecret), null, null).getAccessToken();
		} catch (OAuth2ServiceException ex) {
			logger.warn("Cannot obtain Client Credentials Access Token for clientId {}.", clientId);
			throw new TokenBrokerException("Cannot obtain Client Credentials Access Token from given clientId.", ex);
		}
	}

	@Override
	public String getAccessTokenFromPasswordCredentials(String tokenURL, String clientId, String clientSecret,
			String username, String password) throws TokenBrokerException {
		try {
			return oAuth2TokenService.retrieveAccessTokenViaPasswordGrant(
					URI.create(tokenURL), new ClientCredentials(clientId, clientSecret), username, password, null, null)
					.getAccessToken();
		} catch (OAuth2ServiceException ex) {
			logger.warn("Cannot obtain Token from given user / password.");
			throw new TokenBrokerException("Cannot obtain Token from given user / password.", ex);
		}
	}

}