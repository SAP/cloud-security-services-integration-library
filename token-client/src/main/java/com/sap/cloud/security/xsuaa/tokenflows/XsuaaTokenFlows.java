/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import java.io.Serializable;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.config.ClientIdentity;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

/**
 * A bean that can be {@code @Autowired} by applications to get access to token
 * flow builders. The token flow builders allow for the execution of a client
 * credentials flow (to get a technical user token) and a user token flow (to
 * get an exchange token with different scopes). <br>
 * 
 * This class uses a RestTemplate which it passes on to the builders.
 */
public class XsuaaTokenFlows implements Serializable {
	private static final long serialVersionUID = 2403173341950251507L;

	private final ClientIdentity clientIdentity;
	private final OAuth2TokenService oAuth2TokenService;
	private final OAuth2ServiceEndpointsProvider endpointsProvider;

	/**
	 * @deprecated in favor of
	 *             {@link #XsuaaTokenFlows(OAuth2TokenService, OAuth2ServiceEndpointsProvider, ClientIdentity)}
	 */
	@Deprecated
	public XsuaaTokenFlows(OAuth2TokenService oAuth2TokenService,
			OAuth2ServiceEndpointsProvider endpointsProvider,
			com.sap.cloud.security.xsuaa.client.ClientCredentials clientCredentials) {
		assertNotNull(oAuth2TokenService, "OAuth2TokenService must not be null.");
		assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null");
		assertNotNull(clientCredentials, "ClientCredentials must not be null.");

		this.oAuth2TokenService = oAuth2TokenService;
		this.endpointsProvider = endpointsProvider;
		this.clientIdentity = new ClientCredentials(clientCredentials.getId(), clientCredentials.getSecret());
	}

	/**
	 * Create a new instance of this bean with the given RestTemplate. Applications
	 * should {@code @Autowire} instances of this bean.
	 * 
	 * @param oAuth2TokenService
	 *            the OAuth2TokenService that will be used to send the token
	 *            exchange request.
	 * @param endpointsProvider
	 *            the endpoint provider that serves the token endpoint.
	 * @param clientIdentity
	 *            the OAuth2.0 client identity
	 *
	 *            <pre>
	 *            {@code
	 * String clientId     = "<<get your client id from your service binding>>";
	 * String clientSecret = "<<get your client secret from your service binding>>";
	 * String xsuaaBaseUrl = "<<get your xsuaa base url from service binding>>";
	 *
	 * XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(
	     *                           new DefaultOAuth2TokenService(),
	     *                           new XsuaaDefaultEndpoints(xsuaaBaseUrl),
	     *                           new ClientCredentials(clientId, clientSecret));
	 * }
	 *            </pre>
	 */
	public XsuaaTokenFlows(OAuth2TokenService oAuth2TokenService,
			OAuth2ServiceEndpointsProvider endpointsProvider, ClientIdentity clientIdentity) {
		assertNotNull(oAuth2TokenService, "OAuth2TokenService must not be null.");
		assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null");
		assertNotNull(clientIdentity, "ClientIdentity must not be null.");

		this.oAuth2TokenService = oAuth2TokenService;
		this.endpointsProvider = endpointsProvider;
		this.clientIdentity = clientIdentity;
	}

	/**
	 * Creates a new User Token Flow builder object. Token, authorize and key set
	 * endpoints will be derived relative to the base URI.
	 * 
	 * @return the {@link UserTokenFlow} builder object.
	 * @deprecated Please use {@link #jwtBearerTokenFlow()} instead
	 */
	@Deprecated
	public UserTokenFlow userTokenFlow() {
		return new UserTokenFlow(oAuth2TokenService, endpointsProvider, clientIdentity);
	}

	/**
	 * Creates a new JWT Bearer Token Flow builder object.<br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 *
	 * @return the {@link JwtBearerTokenFlow} builder object.
	 */
	public JwtBearerTokenFlow jwtBearerTokenFlow() {
		return new JwtBearerTokenFlow(oAuth2TokenService, endpointsProvider, clientIdentity);
	}

	/**
	 * Creates a new Client Credentials Flow builder object. <br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @return the {@link ClientCredentialsTokenFlow} builder object.
	 */
	public ClientCredentialsTokenFlow clientCredentialsTokenFlow() {
		return new ClientCredentialsTokenFlow(oAuth2TokenService, endpointsProvider, clientIdentity);
	}

	/**
	 * Creates a new Refresh Token Flow builder object.<br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @return the {@link RefreshTokenFlow} builder object.
	 */
	public RefreshTokenFlow refreshTokenFlow() {
		return new RefreshTokenFlow(oAuth2TokenService, endpointsProvider, clientIdentity);
	}

	/**
	 * Creates a new Refresh Token Flow builder object.<br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 *
	 * @return the {@link PasswordTokenFlow} builder object.
	 */
	public PasswordTokenFlow passwordTokenFlow() {
		return new PasswordTokenFlow(oAuth2TokenService, endpointsProvider, clientIdentity);
	}
}
