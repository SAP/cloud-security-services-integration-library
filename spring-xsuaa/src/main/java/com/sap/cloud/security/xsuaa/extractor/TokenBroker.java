/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import java.net.URI;
import java.util.Map;

import com.sap.cloud.security.client.ClientCredentials;

/**
 *
 * @deprecated in favor of
 *             {@link com.sap.cloud.security.xsuaa.client.OAuth2TokenService}
 *             API. Will be removed with version 3.0.0.
 */
@Deprecated
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
	 * @deprecated in favor of
	 *             {@link com.sap.cloud.security.xsuaa.client.OAuth2TokenService#retrieveAccessTokenViaClientCredentialsGrant(URI, ClientCredentials, String, Map)}
	 */
	@Deprecated
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
	 * @deprecated in favor of
	 *             {@link com.sap.cloud.security.xsuaa.client.OAuth2TokenService#retrieveAccessTokenViaPasswordGrant(URI, ClientCredentials, String, String, String, Map)}
	 */
	public String getAccessTokenFromPasswordCredentials(String tokenURL, String clientId, String clientSecret,
			String username, String password) throws TokenBrokerException;

}