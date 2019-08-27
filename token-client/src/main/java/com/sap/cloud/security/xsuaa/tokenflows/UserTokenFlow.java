package com.sap.cloud.security.xsuaa.tokenflows;

import static com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlowsUtils.buildAuthorities;
import org.springframework.security.jwt.JwtHelper;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.util.Assert;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2AccessToken;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.xsa.security.container.XSTokenRequest;

/**
 * A user token flow builder class. <br>
 * Applications retrieve an instance of this builder from
 * {@link XsuaaTokenFlows} and then create the flow request using a builder
 * pattern.
 */
public class UserTokenFlow {

	private static final String UAA_USER_SCOPE = "uaa.user";
	private static final String SCOPE_CLAIM = "scope";
	private static final String AUTHORITIES = "authorities";

	private XsuaaTokenFlowRequest request;
	private String token;
	private RefreshTokenFlow refreshTokenFlow;
	private OAuth2TokenService tokenService;

	/**
	 * Creates a new instance.
	 *
	 * @param tokenService
	 *            - the {@link OAuth2TokenService} used to execute the final
	 *            request.
	 * @param refreshTokenFlow
	 *            - the refresh token flow
	 * @param endpointsProvider
	 *            - the endpoints provider
	 */
	UserTokenFlow(OAuth2TokenService tokenService, RefreshTokenFlow refreshTokenFlow,
			OAuth2ServiceEndpointsProvider endpointsProvider) {
		Assert.notNull(tokenService, "OAuth2TokenService must not be null.");
		Assert.notNull(refreshTokenFlow, "RefreshTokenFlow must not be null.");
		Assert.notNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null.");

		this.tokenService = tokenService;
		this.refreshTokenFlow = refreshTokenFlow;
		this.request = new XsuaaTokenFlowRequest(endpointsProvider.getTokenEndpoint());
	}

	/**
	 * Sets the JWT token that should be exchanged for another JWT token.
	 *
	 * @param token
	 *            - the JWT token.
	 * @return this builder object.
	 */
	public UserTokenFlow token(String token) {
		Assert.notNull(token, "Token must not be null.");
		this.token = token;
		return this;
	}

	/**
	 * Sets the OAuth 2.0 client ID of the application that the exchanged token is
	 * intended for.<br>
	 *
	 * <b>Note:</b> This is usually not the client ID of the application that
	 * executes this flow, but that of an other application this application intends
	 * to call with the exchanged token.
	 *
	 * @param clientId
	 *            - the OAuth 2.0 client ID of the client for which the exchanged
	 *            token is intended.
	 * @return this builder object.
	 */
	public UserTokenFlow client(String clientId) {
		request.setClientId(clientId);
		return this;
	}

	/**
	 * Sets the OAuth 2.0 client secret of the application that the exchanged token
	 * is intended for.<br>
	 *
	 * <b>Note.</b> It is highly questionable that this is correct. The client
	 * secret should not be known to the application executing this flow.
	 *
	 * @param clientSecret
	 *            - the secret of the OAuth 2.0 client that the exchanged token is
	 *            intended for.
	 * @return this builder object.
	 */
	public UserTokenFlow secret(String clientSecret) {
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
	public UserTokenFlow attributes(Map<String, String> additionalAuthorizationAttributes) {
		this.request.setAdditionalAuthorizationAttributes(additionalAuthorizationAttributes);
		return this;
	}

	public UserTokenFlow subdomain(String subdomain) {
		this.request.setSubdomain(subdomain);
		this.refreshTokenFlow.subdomain(subdomain);
		return this;
	}

	/**
	 * Executes this flow against the XSUAA endpoint. As a result the exchanged JWT
	 * token is returned. <br>
	 * Note, that in a standard flow, only the refresh token would be returned.
	 *
	 * @return the JWT instance returned by XSUAA.
	 * @throws TokenFlowException
	 *             in case of an error.
	 */
	public String execute() throws TokenFlowException {
		checkRequest(request);

		return requestUserToken(request);
	}

	/**
	 * Checks that all mandatory fields of the token flow request have been set.
	 *
	 * @param request
	 *            - the token flow request.
	 * @throws TokenFlowException
	 *             in case not all mandatory fields of the token flow request have
	 *             been set.
	 */
	private void checkRequest(XSTokenRequest request) throws TokenFlowException {
		if (token == null) {
			throw new TokenFlowException(
					"User token not set. Make sure to have called the token() method on UserTokenFlow builder.");
		}

		boolean isUserToken = hasScope(token, UAA_USER_SCOPE);
		if (!isUserToken) {
			throw new TokenFlowException(
					"JWT token does not include scope 'uaa.user'. Only user tokens can be exchanged for another user token.");
		}

		if (!request.isValid()) {
			throw new TokenFlowException(
					"User token flow request is not valid. Make sure all mandatory fields are set.");
		}
	}

	/**
	 * Sends the user token flow request to XSUAA.
	 *
	 * @param request
	 *            - the token flow request.
	 * @return the exchanged JWT from XSUAA.
	 * @throws TokenFlowException
	 *             in case of an error during the flow.
	 */
	private String requestUserToken(XsuaaTokenFlowRequest request) throws TokenFlowException {
		Map<String, String> optionalParameter = null;
		String authorities = buildAuthorities(request);

		if (authorities != null) {
			optionalParameter = new HashMap<>();
			optionalParameter.put(AUTHORITIES, authorities); // places JSON inside the URI !?!
		}

		String refreshToken = null;
		try {
			OAuth2AccessToken accessToken = tokenService
					.retrieveAccessTokenViaUserTokenGrant(request.getTokenEndpoint(),
							new ClientCredentials(request.getClientId(), request.getClientSecret()),
							token, request.getSubdomain(), optionalParameter);

			if (accessToken.getRefreshToken().isPresent()) {
				refreshToken = accessToken.getRefreshToken().get();

				// Now we have a response, that contains a refresh-token. Following the
				// standard,
				// we would now send that token to another service / OAuth 2.0 client and it
				// would
				// there be exchanged for a new JWT token.
				// See:
				// https://docs.cloudfoundry.org/api/uaa/version/4.31.0/index.html#user-token-grant

				// However, XSUAA chooses to do it differently:
				// Using the refresh-token, we retrieve a new user token.
				// We do that with the clientID and clientSecret of the service
				// that should receive the exchanged token !!!
				// This is NOT part of the standard user token exchange !!!
				//
				// Quite frankly it is highly questionable if this is secure.
				// Because now, service A needs to know the OAuth 2.0 credentials
				// of service B to get the exchanged token, when by the standard
				// service A should only send the refresh-token to service B and
				// have service B get the exchange token itself.
				// Service A might now pretend to be Service B and might for example
				// retrieve a client-credentials token on behalf of Service B.

				refreshTokenFlow.refreshToken(refreshToken)
						.client(request.getClientId())
						.secret(request.getClientSecret());

				return refreshTokenFlow.execute();
			} else {
				throw new TokenFlowException(
						"Error requesting token with grant_type 'user_token': response does not provide 'refresh_token'");
			}
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					String.format("Error requesting token with grant_type 'user_token': %s", e.getMessage()));
		}
	}

	/**
	 * Checks if a given scope is contained inside the given token.
	 *
	 * @param token
	 *            - the token to check the scope for.
	 * @param scope
	 *            - the scope to check for.
	 * @return {@code true} if the scope is contained, {@code false} otherwise.
	 */
	private boolean hasScope(String token, String scope) {
		String claims = JwtHelper.decode(token).getClaims();
		try {
			JSONObject rootObject = new JSONObject(claims);
			JSONArray scopesArray = rootObject.getJSONArray(SCOPE_CLAIM);
			for (Iterator scopes = scopesArray.iterator(); scopes.hasNext();)
				if (scopes.next().equals(scope)) {
					return true;
				}
		} catch (JSONException e) {
			return false;
		}
		return false;
	}
}
