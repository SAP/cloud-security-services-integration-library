package com.sap.cloud.security.xsuaa.tokenflows;

import static com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlowsUtils.buildAuthorities;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import javax.annotation.Nullable;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
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
	static final String FF_USE_JWT_BEARER_GRANT_TYPE = "xsuaa.userTokenFlow.useJwtBearer";

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
	 * @param clientCredentials
	 *            - the OAuth client credentials
	 */
	UserTokenFlow(OAuth2TokenService tokenService, RefreshTokenFlow refreshTokenFlow,
			OAuth2ServiceEndpointsProvider endpointsProvider, ClientCredentials clientCredentials) {
		assertNotNull(tokenService, "OAuth2TokenService must not be null.");
		assertNotNull(refreshTokenFlow, "RefreshTokenFlow must not be null.");
		assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null.");
		assertNotNull(clientCredentials, "ClientCredentials must not be null.");

		this.tokenService = tokenService;
		this.refreshTokenFlow = refreshTokenFlow;
		this.request = new XsuaaTokenFlowRequest(endpointsProvider.getTokenEndpoint());
		this.request.setClientId(clientCredentials.getId());
		this.request.setClientSecret(clientCredentials.getSecret());
	}

	/**
	 * Sets the JWT token that should be exchanged for another JWT token.
	 *
	 * @param token
	 *            - the JWT token.
	 * @return this builder object.
	 */
	public UserTokenFlow token(String token) {
		assertNotNull(token, "Token must not be null.");
		this.token = token;
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
	 * Sets the subdomain (tenant) the token is requested for.<br>
	 *
	 * @param subdomain
	 *            - the subdomain.
	 * @return this builder.
	 */
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
	 * @throws IllegalStateException
	 *             - in case not all mandatory fields of the token flow request have
	 *             been set.
	 * @throws TokenFlowException
	 *             - in case of an error during the flow, or when the token cannot
	 *             be refreshed.
	 */
	public OAuth2TokenResponse execute() throws TokenFlowException {
		checkRequest(request);

		return requestUserToken(request);
	}

	/**
	 * Checks that all mandatory fields of the token flow request have been set.
	 *
	 * @param request
	 *            - the token flow request.
	 * @throws IllegalArgumentException
	 *             - in case not all mandatory fields of the token flow request have
	 *             been set.
	 * @throws IllegalStateException
	 *             - in case the user token has not been set or does not include
	 *             scope 'uaa.user'
	 */
	private void checkRequest(XSTokenRequest request) throws IllegalArgumentException {
		if (token == null) {
			throw new IllegalStateException(
					"User token not set. Make sure to have called the token() method on UserTokenFlow builder.");
		}

		boolean isUserToken = hasScope(token, UAA_USER_SCOPE);
		if (!isUserToken) {
			throw new IllegalStateException(
					"JWT token does not include scope 'uaa.user'. Only user tokens can be exchanged for another user token.");
		}

		if (!request.isValid()) {
			throw new IllegalArgumentException(
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
	private OAuth2TokenResponse requestUserToken(XsuaaTokenFlowRequest request) throws TokenFlowException {
		Map<String, String> optionalParameter = null;
		String authorities = buildAuthorities(request);

		if (authorities != null) {
			optionalParameter = new HashMap<>();
			optionalParameter.put(AUTHORITIES, authorities); // places JSON inside the URI !?!
		}

		String refreshToken = null;
		try {
			boolean useJwtBearerGrant = Boolean.parseBoolean(readFromPropertyFile(FF_USE_JWT_BEARER_GRANT_TYPE));
			if (useJwtBearerGrant) {
				/*
				 * As soon as JWT bearer token supports scopes, we can just use this one to get
				 * an user token
				 */
				return tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
						request.getTokenEndpoint(),
						new ClientCredentials(request.getClientId(), request.getClientSecret()),
						token,
						request.getSubdomain(),
						optionalParameter);

			}
			OAuth2TokenResponse accessToken = tokenService
					.retrieveAccessTokenViaUserTokenGrant(request.getTokenEndpoint(),
							new ClientCredentials(request.getClientId(), request.getClientSecret()),
							token, request.getSubdomain(), optionalParameter);

			if (accessToken.getRefreshToken() != null) {
				refreshToken = accessToken.getRefreshToken();

				// Now we have a response, that contains a refresh-token. Following the
				// standard, we would now send that token to another service / OAuth 2.0 client
				// and it would there be exchanged for a new JWT token.
				// See:
				// https://docs.cloudfoundry.org/api/uaa/version/4.31.0/index.html#user-token-grant

				// However, XSUAA chooses to do it differently:
				// Using the refresh-token, we retrieve a new user token.
				// We do that with the clientID and clientSecret of the service
				// that should receive the exchanged token !!!
				// This is NOT part of the standard user token exchange !!!

				refreshTokenFlow.refreshToken(refreshToken);

				return refreshTokenFlow.execute();
			} else {
				throw new TokenFlowException(
						"Error requesting token with grant_type 'user_token': response does not provide 'refresh_token'");
			}
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					String.format("Error requesting token with grant_type 'user_token': %s", e.getMessage()), e);
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
		String claims = new Base64JwtDecoder().decode(token).getPayload();
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

	@Nullable
	private String readFromPropertyFile(String property) {
		String rootPath = Thread.currentThread().getContextClassLoader().getResource("").getPath();
		String appConfigPath = rootPath + "application.properties";

		Properties appProps = new Properties();
		try {
			appProps.load(new FileInputStream(appConfigPath));
			return appProps.getProperty(property);
		} catch (IOException e) {
			return null;
		}
	}

}
