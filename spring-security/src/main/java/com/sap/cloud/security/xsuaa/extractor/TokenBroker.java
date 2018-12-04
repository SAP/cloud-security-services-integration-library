package com.sap.cloud.security.xsuaa.extractor;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;

import com.sap.cloud.security.xsuaa.token.service.TokenBrokerException;

/**
 *
 *
 */
public interface TokenBroker {


	/**
	 * Exchange clientid, client secret against a OAuth token
	 * 
	 * @param tokenURL
	 *            tokenURL
	 * @param clientId
	 *            clientId
	 * @param clientSecret
	 *            clientSecret
	 * @return OAuth2AccessToken
	 * @throws TokenBrokerException
	 *             TokenBrokerException
	 */
	public DefaultOAuth2AccessToken getAccessTokenFromClientCredentials(String tokenURL, String clientId, String clientSecret) throws TokenBrokerException;


	/**
	 * Exchange username, password, client id, client secret against a token
	 * 
	 * @param tokenURL
	 *            tokenURL
	 * @param clientId
	 *            clientId
	 * @param clientSecret
	 *            clientSecret
	 * @param username
	 *            username
	 * @param password
	 *            password
	 * @return OAuth2AccessToken
	 * @throws TokenBrokerException
	 *             TokenBrokerException
	 */
	public DefaultOAuth2AccessToken getAccessTokenFromPasswordCredentials(String tokenURL, String clientId, String clientSecret, String username, String password) throws TokenBrokerException;

}