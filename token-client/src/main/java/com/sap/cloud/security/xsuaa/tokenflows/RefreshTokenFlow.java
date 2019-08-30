package com.sap.cloud.security.xsuaa.tokenflows;

import org.springframework.util.Assert;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2AccessToken;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.xsa.security.container.XSTokenRequest;

/**
 * A refresh token flow builder. <br>
 * Applications can use this flow exchange a given refresh token for a
 * (refreshed) JWT token.
 */
public class RefreshTokenFlow {

	private XsuaaTokenFlowRequest request;
	private String refreshToken;
	private OAuth2TokenService tokenService;

	/**
	 * Creates a new instance.
	 *
	 * @param tokenService
	 *            - the {@link OAuth2TokenService} used to execute the final
	 *            request.
	 * @param endpointsProvider
	 *            - the endpoints provider
	 * @param clientCredentials
	 *            - the OAuth client credentials
	 */
	RefreshTokenFlow(OAuth2TokenService tokenService, OAuth2ServiceEndpointsProvider endpointsProvider,
			ClientCredentials clientCredentials) {
		Assert.notNull(tokenService, "OAuth2TokenService must not be null.");
		Assert.notNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null.");
		Assert.notNull(clientCredentials, "ClientCredentials must not be null.");

		this.tokenService = tokenService;
		this.request = new XsuaaTokenFlowRequest(endpointsProvider.getTokenEndpoint());
		this.request.setClientId(clientCredentials.getId());
		this.request.setClientSecret(clientCredentials.getSecret());
	}

	public RefreshTokenFlow subdomain(String subdomain) {
		request.setSubdomain(subdomain);
		return this;
	}

	/**
	 * Sets the mandatory refresh token to be exchanged for a (refreshed) JWT.
	 * 
	 * @param refreshToken
	 *            - the refresh token to be exchanged for a JWT.
	 * @return this builder object.
	 */
	public RefreshTokenFlow refreshToken(String refreshToken) {
		Assert.notNull(refreshToken, "RefreshToken must not be null.");
		this.refreshToken = refreshToken;
		return this;
	}

	/**
	 * Executes the refresh token flow against XSUAA.
	 * 
	 * @return the refreshed OAuth access token returned by XSUAA or an exception in
	 *         case the token could not be refreshed.
	 * @throws TokenFlowException
	 *             in case of an error during the flow, or when the token cannot be
	 *             refreshed.
	 */
	public String execute() throws TokenFlowException {
		checkRequest(request);

		return refreshToken(refreshToken, request);
	}

	/**
	 * Checks that all mandatory fields of the token flow request have been set.
	 * Otherwise throws an exception.
	 * 
	 * @param request
	 *            - the request to check.
	 * @throws TokenFlowException
	 *             in case not all mandatory fields of the token flow request have
	 *             been set.
	 */
	private void checkRequest(XSTokenRequest request) throws TokenFlowException {
		if (refreshToken == null) {
			throw new TokenFlowException(
					"Refresh token not set. Make sure to have called the refreshToken() method on RefreshTokenFlow builder.");
		}

		if (!request.isValid()) {
			throw new TokenFlowException(
					"Refresh token flow request is not valid. Make sure all mandatory fields are set.");
		}
	}

	/**
	 * Refreshes the token based on the given {@code refreshToken} instance.
	 * 
	 * @param refreshToken
	 *            - the (opaque) refresh token.
	 * @param request
	 *            - the token flow request to execute.
	 * @return the encoded OAuth access token received in exchange for the refresh
	 *         token.
	 * @throws TokenFlowException
	 *             in case of an error in the flow.
	 */
	private String refreshToken(String refreshToken, XsuaaTokenFlowRequest request) throws TokenFlowException {
		try {
			OAuth2AccessToken accessToken = tokenService.retrieveAccessTokenViaRefreshToken(request.getTokenEndpoint(),
					new ClientCredentials(request.getClientId(), request.getClientSecret()), refreshToken,
					request.getSubdomain());
			return accessToken.getValue();
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					String.format("Error refreshing token with grant_type 'refresh_token': %s", e.getMessage()));
		}
	}
}
