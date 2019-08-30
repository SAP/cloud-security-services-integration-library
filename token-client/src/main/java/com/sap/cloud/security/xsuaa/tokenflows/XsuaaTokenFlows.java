package com.sap.cloud.security.xsuaa.tokenflows;

import java.io.Serializable;

import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;

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

	private final ClientCredentials clientCredentials;
	private RestOperations restOperations;
	private OAuth2ServiceEndpointsProvider endpointsProvider;

	/**
	 * Create a new instance of this bean with the given RestTemplate. Applications
	 * should {@code @Autowire} instances of this bean.
	 * 
	 * @param restOperations
	 *            the RestTemplate instance that will be used to send the token
	 *            exchange request.
	 */
	public XsuaaTokenFlows(RestOperations restOperations,
			OAuth2ServiceEndpointsProvider endpointsProvider, ClientCredentials clientCredentials) {
		Assert.notNull(restOperations, "RestOperations must not be null.");
		Assert.notNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null.");
		Assert.notNull(clientCredentials, "ClientCredentials must not be null.");

		this.restOperations = restOperations;
		this.endpointsProvider = endpointsProvider;
		this.clientCredentials = clientCredentials;
	}

	/**
	 * Creates a new User Token Flow builder object. The token passed needs to
	 * contain the scope {@code uaa.user}, otherwise an exception will be thrown
	 * when the flow is executed. <br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @return the {@link UserTokenFlow} builder object.
	 */
	public UserTokenFlow userTokenFlow() {
		OAuth2TokenService tokenService = initializeTokenService();
		RefreshTokenFlow refreshTokenFlow = new RefreshTokenFlow(tokenService, endpointsProvider, clientCredentials);

		return new UserTokenFlow(tokenService, refreshTokenFlow, endpointsProvider, clientCredentials);
	}

	/**
	 * Creates a new Client Credentials Flow builder object. <br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @return the {@link ClientCredentialsTokenFlow} builder object.
	 */
	public ClientCredentialsTokenFlow clientCredentialsTokenFlow() {
		return new ClientCredentialsTokenFlow(initializeTokenService(), endpointsProvider, clientCredentials);
	}

	/**
	 * Creates a new Refresh Token Flow builder object.<br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @return the {@link ClientCredentialsTokenFlow} builder object.
	 */
	public RefreshTokenFlow refreshTokenFlow() {
		return new RefreshTokenFlow(initializeTokenService(), endpointsProvider, clientCredentials);
	}

	OAuth2TokenService initializeTokenService() {
		return new XsuaaOAuth2TokenService(restOperations);
	}
}
