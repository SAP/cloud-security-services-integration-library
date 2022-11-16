/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.client.HttpClientException;
import com.sap.cloud.security.config.CredentialType;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.*;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

/**
 * IAS token and XSUAA token exchange class. Facilitates token exchange between
 * IAS and XSUAA
 */
class IasXsuaaExchangeBroker {

	private static final Logger LOGGER = LoggerFactory.getLogger(IasXsuaaExchangeBroker.class);
	private XsuaaTokenFlows xsuaaTokenFlows;

	private IasXsuaaExchangeBroker() {
	}

	static IasXsuaaExchangeBroker build(OAuth2ServiceConfiguration configuration, OAuth2TokenService tokenService) {
		IasXsuaaExchangeBroker broker = new IasXsuaaExchangeBroker();
		Assertions.assertNotNull(configuration, "Service configuration must not be null");
		Assertions.assertNotNull(tokenService, "Oauth2 Token Service must not be null");
		LOGGER.debug("Initializing XsuaaTokenFlow ({} based authentication)",
				configuration.getCredentialType() == CredentialType.X509 ? "certificate" : "client secret");
		broker.xsuaaTokenFlows = new XsuaaTokenFlows(
				tokenService,
				new XsuaaDefaultEndpoints(configuration),
				configuration.getClientIdentity());
		return broker;
	}

	/**
	 * Request a Xsuaa token using Ias token as a grant.
	 *
	 * @param token
	 *            decoded IAS token
	 * @return encoded Xsuaa token
	 */
	@Nullable
	public String resolve(Token token) throws TokenFlowException, HttpClientException {
		OAuth2TokenResponse tokenResponse = xsuaaTokenFlows.userTokenFlow().token(token).execute();
		LOGGER.debug("Response token from Ias to Xsuaa token exchange {}", tokenResponse.getAccessToken());
		return tokenResponse.getAccessToken();
	}

}
