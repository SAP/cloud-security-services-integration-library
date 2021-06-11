/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.mtls.HttpClient;
import com.sap.cloud.security.xsuaa.mtls.ServiceClientException;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * IAS token and XSUAA token exchange class. Facilitates token exchange between
 * IAS and XSUAA
 */
class IasXsuaaExchangeBroker {

	private static final Logger logger = LoggerFactory.getLogger(IasXsuaaExchangeBroker.class);

	/**
	 * Request a Xsuaa token using Ias token as a grant.
	 *
	 * @param httpClient
	 *            http client that will perform the request
	 * @param token
	 *            decoded IAS token
	 * @param serviceConfiguration
	 *            Xsuaa service configuration
	 * @return encoded Xsuaa token
	 */
	@Nullable
	public String doIasToXsuaaXchange(CloseableHttpClient httpClient, Token token,
			@Nonnull OAuth2ServiceConfiguration serviceConfiguration) throws TokenFlowException, ServiceClientException {
		Assertions.assertNotNull(serviceConfiguration, "Service configuration must not be null");

		logger.debug("Initializing XsuaaTokenFlow for token xchange using {} authentication method", serviceConfiguration.getCredentialType());
		logger.debug("Resolving http client " + httpClient == null ? "based on service configuration": "using custom httpClient provided");
		XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(
				new DefaultOAuth2TokenService(httpClient == null ? HttpClient.create(serviceConfiguration.getClientIdentity()).getCloseableHttpClient() : httpClient),
				new XsuaaDefaultEndpoints(serviceConfiguration),
				serviceConfiguration.getClientIdentity());
		OAuth2TokenResponse tokenResponse = tokenFlows.userTokenFlow().token(token).execute();
		logger.debug("Response token from Ias to Xsuaa token exchange {}", tokenResponse.getAccessToken());
		return tokenResponse.getAccessToken();
	}

}
