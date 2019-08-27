package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.client.*;
import com.sap.xsa.security.container.XSTokenRequest;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlowsUtils.buildAuthorities;

/**
 * A client credentials flow builder class. Applications retrieve an instance of
 * this builder from {@link XsuaaTokenFlows} and then create the flow request
 * using a builder pattern.
 */
public class ClientCredentialsTokenFlow {

	private static final String AUTHORITIES = "authorities";

	private XsuaaTokenFlowRequest request;
	private OAuth2TokenService tokenService;

	/**
	 * Creates a new instance.
	 *
	 * @param tokenService
	 *            - the {@link OAuth2TokenService} used to execute the final
	 *            request.
	 * @param endpointsProvider
	 *            - the endpoints provider
	 */
	ClientCredentialsTokenFlow(OAuth2TokenService tokenService, OAuth2ServiceEndpointsProvider endpointsProvider) {
		Assert.notNull(tokenService, "OAuth2TokenService must not be null.");
		Assert.notNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null.");

		this.tokenService = tokenService;
		this.request = new XsuaaTokenFlowRequest(endpointsProvider.getTokenEndpoint());
	}

	/**
	 * Adds the OAuth 2.0 client ID to the request.<br>
	 * The ID needs to be that of the OAuth client that requests the token.
	 *
	 * @param clientId
	 *            - the ID of the OAuth 2.0 client requesting the token.
	 * @return this builder.
	 */
	public ClientCredentialsTokenFlow client(String clientId) {
		request.setClientId(clientId);
		return this;
	}

	/**
	 * Adds the OAuth 2.0 client's secret to this request.<br>
	 * The secret needs to be the one of the client that requests the token.
	 *
	 * @param clientSecret
	 *            - the secret of the OAuth 2.0 client requesting the token.
	 * @return this builder.
	 */
	public ClientCredentialsTokenFlow secret(String clientSecret) {
		request.setClientSecret(clientSecret);
		return this;
	}

	/**
	 * Adds additional authorization attributes to the request. <br>
	 * Clients can use this to request additional attributes in the
	 * {@code 'az_attr'} claim of the returned token.
	 *
	 * @param additionalAuthorizationAttributes
	 *            - the additional attributes.
	 * @return this builder.
	 */
	public ClientCredentialsTokenFlow attributes(Map<String, String> additionalAuthorizationAttributes) {
		request.setAdditionalAuthorizationAttributes(additionalAuthorizationAttributes);
		return this;
	}

	public ClientCredentialsTokenFlow subdomain(String subdomain) {
		request.setSubdomain(subdomain);
		return this;
	}

	/**
	 * Executes the token flow and returns a JWT token from XSUAA.
	 *
	 * @return the encoded OAuth access token returned by XSUAA.
	 * @throws TokenFlowException
	 *             in case of token flow errors.
	 */
	public String execute() throws TokenFlowException {
		checkRequest(request);

		return requestTechnicalUserToken(request);
	}

	/**
	 * Checks if the built request is valid. Throws an exception if not all
	 * mandatory fields are filled.
	 *
	 * @param request
	 *            - the token flow request.
	 * @throws TokenFlowException
	 *             in case the request does not have all mandatory fields set.
	 */
	private void checkRequest(XSTokenRequest request) throws TokenFlowException {
		if (!request.isValid()) {
			throw new TokenFlowException(
					"Client credentials flow request is not valid. Make sure all mandatory fields are set.");
		}
	}

	/**
	 * Requests the client credentials token from XSUAA.
	 *
	 * @param request
	 *            - the token request.
	 * @return the encoded OAuth access token returned by XSUAA.
	 * @throws TokenFlowException
	 *             in case of an error during the flow.
	 */
	@Nullable
	private String requestTechnicalUserToken(XsuaaTokenFlowRequest request) throws TokenFlowException {
		Map requestParameter = null;
		String authorities = buildAuthorities(request);

		if (authorities != null) {
			requestParameter = new HashMap();
			requestParameter.put(AUTHORITIES, authorities); // places JSON inside the URI
		}

		try {
			OAuth2AccessToken accessToken = tokenService
					.retrieveAccessTokenViaClientCredentialsGrant(request.getTokenEndpoint(),
							new ClientCredentials(request.getClientId(), request.getClientSecret()),
							request.getSubdomain(), requestParameter);
			return accessToken.getValue();
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					String.format("Error requesting user token with grant_type 'client_credentials': %s",
							e.getMessage()));
		}
	}
}
