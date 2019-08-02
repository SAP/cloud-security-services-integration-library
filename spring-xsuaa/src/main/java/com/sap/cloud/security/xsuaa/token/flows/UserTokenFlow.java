package com.sap.cloud.security.xsuaa.token.flows;

import com.sap.cloud.security.xsuaa.backend.OAuth2Server;
import com.sap.cloud.security.xsuaa.backend.OAuth2ServerException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowsUtils.buildAuthorities;

/**
 * A user token flow builder class. <br>
 * Applications retrieve an instance of this builder from
 * {@link XsuaaTokenFlows} and then create the flow request using a builder
 * pattern.
 */
public class UserTokenFlow {

	private static final String REFRESH_TOKEN = "refresh_token";
	private static final String CLIENT_ID = "client_id";
	private static final String TOKEN = "token";
	private static final String RESPONSE_TYPE = "response_type";
	private static final String USER_TOKEN = "user_token";
	private static final String UAA_USER_SCOPE = "uaa.user";
	private static final String SCOPE_CLAIM = "scope";
	private static final String GRANT_TYPE = "grant_type";
	private static final String AUTHORITIES = "authorities";

	private XsuaaTokenFlowRequest request;
	private Jwt token;
	private RefreshTokenFlow refreshTokenFlow;
	private OAuth2Server oAuth2Server;

	/**
	 * Creates a new instance.
	 *
	 * @param oAuth2Server
	 *            - the {@link OAuth2Server} used to execute the final request.
	 * @param refreshTokenFlow
	 * 			  - the refresh token flow
	 */
	UserTokenFlow(OAuth2Server oAuth2Server, RefreshTokenFlow refreshTokenFlow) {
		Assert.notNull(oAuth2Server, "OAuth2Server must not be null.");
		Assert.notNull(refreshTokenFlow, "RefreshTokenFlow must not be null.");

		this.oAuth2Server = oAuth2Server;
		this.refreshTokenFlow = refreshTokenFlow;
		this.request = new XsuaaTokenFlowRequest(oAuth2Server.getEndpointsProvider());
	}

	/**
	 * Sets the JWT token that should be exchanged for another JWT token.
	 * 
	 * @param token
	 *            - the JWT token.
	 * @return this builder object.
	 */
	public UserTokenFlow token(Jwt token) {
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

	/**
	 * Executes this flow against the XSUAA endpoint. As a result the exchanged JWT
	 * token is returned. <br>
	 * Note, that in a standard flow, only the refresh token would be returned.
	 * 
	 * @return the JWT instance returned by XSUAA.
	 * @throws TokenFlowException
	 *             in case of an error.
	 */
	public Jwt execute() throws TokenFlowException {
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
	private void checkRequest(XsuaaTokenFlowRequest request) throws TokenFlowException {
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
	private Jwt requestUserToken(XsuaaTokenFlowRequest request) throws TokenFlowException {
		Map<String, String> requestParameter = new HashMap<>();

		requestParameter.put(GRANT_TYPE, USER_TOKEN);
		requestParameter.put(RESPONSE_TYPE, TOKEN);
		requestParameter.put(CLIENT_ID, request.getClientId());

		String authorities = buildAuthorities(request);
		if (authorities != null) {
			requestParameter.put(AUTHORITIES, authorities); // places JSON inside the URI !?!
		}

		String refreshToken = null;
		try {
			Map clientCredentialsToken = oAuth2Server.requestToken(requestParameter, token.getTokenValue());
			refreshToken = clientCredentialsToken.get(REFRESH_TOKEN).toString();
		} catch (OAuth2ServerException e) {
			throw new TokenFlowException(String.format("Error requesting token with grant_type %s: %s", USER_TOKEN, e.getMessage()));
		}

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
	private boolean hasScope(Jwt token, String scope) {
		List<String> scopes = token.getClaimAsStringList(SCOPE_CLAIM);
		return scopes.contains(scope);
	}
}
