package com.sap.cloud.security.xsuaa.tokenflows;

import static com.sap.cloud.security.xsuaa.ObjectsUtil.assertNotNull;
import static com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlowsUtils.buildAuthorities;

import java.util.HashMap;
import java.util.Map;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.xsa.security.container.XSTokenRequest;

import javax.annotation.Nullable;

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
	 * @param clientCredentials
	 *            - the OAuth client credentials
	 */
	ClientCredentialsTokenFlow(OAuth2TokenService tokenService, OAuth2ServiceEndpointsProvider endpointsProvider,
			ClientCredentials clientCredentials) {
		assertNotNull(tokenService, "OAuth2TokenService must not be null.");
		assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null.");
		assertNotNull(clientCredentials, "ClientCredentials must not be null.");

		this.tokenService = tokenService;
		this.request = new XsuaaTokenFlowRequest(endpointsProvider.getTokenEndpoint());
		this.request.setClientId(clientCredentials.getId());
		this.request.setClientSecret(clientCredentials.getSecret());
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

	/**
	 * Sets the subdomain (tenant) the token is requested for.<br>
	 *
	 * @param subdomain
	 *            - the subdomain.
	 * @return this builder.
	 */
	public ClientCredentialsTokenFlow subdomain(String subdomain) {
		request.setSubdomain(subdomain);
		return this;
	}

	/**
	 * Executes the token flow and returns a JWT token from XSUAA.
	 *
	 * @return the encoded OAuth access token returned by XSUAA.
	 * @throws IllegalArgumentException
	 *             - in case not all mandatory fields of the token flow request have
	 *             been set.
	 * @throws TokenFlowException
	 *             - in case of an error during the flow, or when the token cannot
	 *             be refreshed.
	 */
	public OAuth2TokenResponse execute() throws IllegalArgumentException, TokenFlowException {
		checkRequest(request);

		return requestTechnicalUserToken(request);
	}

	/**
	 * Checks if the built request is valid. Throws an exception if not all
	 * mandatory fields are filled.
	 *
	 * @param request
	 *            - the token flow request.
	 * @throws IllegalArgumentException
	 *             in case the request does not have all mandatory fields set.
	 */
	private void checkRequest(XSTokenRequest request) throws IllegalArgumentException {
		if (!request.isValid()) {
			throw new IllegalArgumentException(
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
	private OAuth2TokenResponse requestTechnicalUserToken(XsuaaTokenFlowRequest request) throws TokenFlowException {
		Map requestParameter = null;
		String authorities = buildAuthorities(request);

		if (authorities != null) {
			requestParameter = new HashMap();
			requestParameter.put(AUTHORITIES, authorities); // places JSON inside the URI
		}

		try {
			OAuth2TokenResponse accessToken = tokenService
					.retrieveAccessTokenViaClientCredentialsGrant(request.getTokenEndpoint(),
							new ClientCredentials(request.getClientId(), request.getClientSecret()),
							request.getSubdomain(), requestParameter);
			return accessToken;
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					String.format("Error requesting user token with grant_type 'client_credentials': %s",
							e.getMessage()),
					e);
		}
	}
}
