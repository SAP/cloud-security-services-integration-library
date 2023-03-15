/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.CredentialType;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

/**
 * IAS token and XSUAA token exchange and resolution class. Can be used to
 * distinguish between IAS and XSUAA tokens. Controls token exchange between IAS
 * and XSUAA by using IAS_XSUAA_XCHANGE_ENABLED environment variable flag
 */
public class IasXsuaaExchangeBroker implements BearerTokenResolver {

	private static final Logger logger = LoggerFactory.getLogger(IasXsuaaExchangeBroker.class);
	private static final String AUTH_HEADER = "Authorization";
	private final XsuaaTokenFlows xsuaaTokenFlows;

	public IasXsuaaExchangeBroker(XsuaaTokenFlows xsuaaTokenFlows) {
		this.xsuaaTokenFlows = xsuaaTokenFlows;
	}

	public IasXsuaaExchangeBroker(OAuth2ServiceConfiguration configuration, OAuth2TokenService tokenService) {
		ClientIdentity clientIdentity = configuration.getClientIdentity();
		logger.debug("Initializing XsuaaTokenFlow ({} based authentication)",
				configuration.getCredentialType() == CredentialType.X509 ? "certificate" : "client secret");
		this.xsuaaTokenFlows = new XsuaaTokenFlows(
				tokenService,
				new XsuaaDefaultEndpoints(configuration),
				clientIdentity);

	}

	@Override
	@Nullable
	public String resolve(HttpServletRequest request) {
		String oAuth2Token = extractTokenFromRequest(request);
		if (oAuth2Token == null) {
			logger.info("Request did not have Authorization header containing bearer token, skipping token exchange.");
			return null;
		}
		try {
			DecodedJwt decodedJwt = TokenUtil.decodeJwt(oAuth2Token);
			if (!TokenUtil.isXsuaaToken(decodedJwt)) {
				return doIasXsuaaXchange(decodedJwt);
			}
		} catch (JSONException e) {
			logger.error("Couldn't decode the token: {}", e.getMessage());
		}
		return oAuth2Token;
	}

	/**
	 * Request a Xsuaa token using Ias token as a grant.
	 *
	 * @param decodedJwt
	 *            decoded Jwt token
	 * @return encoded Xsuaa token
	 */
	@Nullable
	String doIasXsuaaXchange(DecodedJwt decodedJwt) {
		try {
			return xsuaaTokenFlows.userTokenFlow().token(createToken(decodedJwt)).execute().getAccessToken();
		} catch (TokenFlowException e) {
			logger.error("Xsuaa token request failed {}", e.getMessage());
		}
		return null;
	}

	/**
	 * Resolves the encoded token to Token class
	 * 
	 * @param decodedJwt
	 *            decoded Jwt
	 * @return IasToken class if provided Jwt token couldn't be parsed
	 */
	private Token createToken(DecodedJwt decodedJwt) {
		Jwt jwt = TokenUtil.parseJwt(decodedJwt);
		return new IasToken(jwt);
	}

	@Nullable
	private String extractTokenFromRequest(HttpServletRequest request) {
		String authHeader = request.getHeader(AUTH_HEADER);

		if (authHeader != null && authHeader.toLowerCase().startsWith("bearer")) {
			return authHeader.substring("bearer".length()).trim();
		}
		return null;
	}
}
