/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import java.net.URI;
import java.util.Map;

import com.sap.cloud.security.config.ClientIdentity;

/**
 *
 * @deprecated in favor of
 *             {@link com.sap.cloud.security.xsuaa.client.OAuth2TokenService}
 *             API. as it doesn't support certificate based communication. Will
 *             be removed with version 3.0.0.
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
	 *             {@link com.sap.cloud.security.xsuaa.client.OAuth2TokenService#retrieveAccessTokenViaClientCredentialsGrant(URI, ClientIdentity, String, Map)}
	 *             as it doesn't support certificate based communication.
	 */
	@Deprecated
	String getAccessTokenFromClientCredentials(String tokenURL, String clientId, String clientSecret)
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
	 *             {@link com.sap.cloud.security.xsuaa.client.OAuth2TokenService#retrieveAccessTokenViaPasswordGrant(URI, ClientIdentity, String, String, String, Map)}.
	 *             as it doesn't support certificate based communication.
	 */
	String getAccessTokenFromPasswordCredentials(String tokenURL, String clientId, String clientSecret,
			String username, String password) throws TokenBrokerException;

}