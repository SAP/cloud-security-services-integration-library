package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2Service;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

/**
 * A bean that can be {@code @Autowired} by applications to get access to token
 * flow builders. The token flow builders allow for the execution of a client
 * credentials flow (to get a technical user token) and a user token flow (to
 * get an exchange token with different scopes). <br>
 * 
 * This class uses a RestTemplate which it passes on to the builders.
 */
public class XsuaaTokenFlows {

	private RestTemplate restTemplate;
	private VariableKeySetUriTokenDecoder tokenDecoder;
	private OAuth2ServiceEndpointsProvider endpointsProvider;

	/**
	 * Create a new instance of this bean with the given RestTemplate. Applications
	 * should {@code @Autowire} instances of this bean.
	 * 
	 * @param restTemplate
	 *            the RestTemplate instance that will be used to send the token
	 *            exchange request.
	 * @param tokenDecoder
	 *            the {@link VariableKeySetUriTokenDecoder} instance used internally
	 *            to decode a Jwt token.
	 */
	public XsuaaTokenFlows(RestTemplate restTemplate, VariableKeySetUriTokenDecoder tokenDecoder,
			OAuth2ServiceEndpointsProvider endpointsProvider) {
		Assert.notNull(restTemplate, "RestTemplate must not be null.");
		Assert.notNull(tokenDecoder, "TokenDecoder must not be null.");
		Assert.notNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null.");

		this.restTemplate = restTemplate;
		this.tokenDecoder = tokenDecoder;
		this.endpointsProvider = endpointsProvider;
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
		RefreshTokenFlow refreshTokenFlow = new RefreshTokenFlow(tokenService, tokenDecoder, endpointsProvider);

		return new UserTokenFlow(tokenService, refreshTokenFlow, endpointsProvider);
	}

	/**
	 * Creates a new Client Credentials Flow builder object. <br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @return the {@link ClientCredentialsTokenFlow} builder object.
	 */
	public ClientCredentialsTokenFlow clientCredentialsTokenFlow() {
		return new ClientCredentialsTokenFlow(initializeTokenService(), tokenDecoder, endpointsProvider);
	}

	/**
	 * Creates a new Refresh Token Flow builder object.<br>
	 * Token, authorize and key set endpoints will be derived relative to the base
	 * URI.
	 * 
	 * @return the {@link ClientCredentialsTokenFlow} builder object.
	 */
	public RefreshTokenFlow refreshTokenFlow() {
		return new RefreshTokenFlow(initializeTokenService(), tokenDecoder, endpointsProvider);
	}

	OAuth2TokenService initializeTokenService() {
		return new OAuth2Service(restTemplate);
	}
}
