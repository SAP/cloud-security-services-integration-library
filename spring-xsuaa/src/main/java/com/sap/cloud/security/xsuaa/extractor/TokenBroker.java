package com.sap.cloud.security.xsuaa.extractor;

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
	 * @return String
	 * @throws TokenBrokerException
	 *             TokenBrokerException
	 */
	public String getAccessTokenFromClientCredentials(String tokenURL, String clientId, String clientSecret)
			throws TokenBrokerException;

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
	 * @return String
	 * @throws TokenBrokerException
	 *             TokenBrokerException
	 */
	public String getAccessTokenFromPasswordCredentials(String tokenURL, String clientId, String clientSecret,
			String username, String password) throws TokenBrokerException;

}