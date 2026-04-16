package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.client.*;

import javax.annotation.Nonnull;
import java.util.*;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlowsUtils.buildAdditionalAuthoritiesJson;

/**
 * A JWT bearer token flow builder. <br> Applications can use this flow to exchange a given user token for a new JWT
 * token.
 */
public class JwtBearerTokenFlow {

	private final OAuth2TokenService tokenService;
	private final OAuth2ServiceEndpointsProvider endpointsProvider;
	private final ClientIdentity clientIdentity;
	private final Map<String, String> optionalParameters = new HashMap<>();
	private String bearerToken;
	private String xZid;
	private List<String> scopes = new ArrayList<>();
	private String subdomain;
	private boolean disableCache;
	private boolean opaque = false;

	public JwtBearerTokenFlow(@Nonnull OAuth2TokenService tokenService,
			@Nonnull OAuth2ServiceEndpointsProvider endpointsProvider,
			@Nonnull ClientIdentity clientIdentity) {
		assertNotNull(tokenService, "OAuth2TokenService must not be null!");
		assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null!");
		assertNotNull(clientIdentity, "ClientIdentity must not be null!");

		this.tokenService = tokenService;
		this.endpointsProvider = endpointsProvider;
		this.clientIdentity = clientIdentity;
	}

	/**
	 * Sets the bearer token that should be exchanged for another JWT token.
	 *
	 * @param bearerToken
	 * 		- the bearer token.
	 * @return this builder.
	 */
	public JwtBearerTokenFlow token(@Nonnull String bearerToken) {
		assertNotNull(bearerToken, "Bearer token must not be null.");
		this.bearerToken = bearerToken;
		return this;
	}

	/**
	 * Sets the JWT token that should be exchanged for another JWT token. This setter also extracts the zid(zone id)
	 * claim from the token and sets it in the X-zid header, therefore {@link JwtBearerTokenFlow#zoneId(String)}} is not
	 * required to be used.
	 *
	 * @param token
	 * 		- the Token.
	 * @return this builder.
	 */
	public JwtBearerTokenFlow token(@Nonnull Token token) {
		assertNotNull(token, "Token must not be null.");
		this.bearerToken = token.getTokenValue();
		this.xZid = token.getZoneId();
		return this;
	}

	/**
	 * Sets the zid(zone id) of the tenant<br>
	 *
	 * @param zoneId
	 * 		- the zoneId.
	 * @return this builder.
	 */
	public JwtBearerTokenFlow zoneId(String zoneId) {
		this.xZid = zoneId;
		return this;
	}

	/**
	 * Sets the scope attribute for the token request. This will restrict the scope of the created token to the scopes
	 * provided. By default the scope is not restricted and the created token contains all granted scopes.
	 * <p>
	 * If you specify a scope that is not authorized for the user, the token request will fail.
	 *
	 * @param scopes
	 * 		- one or many scopes as string.
	 * @return this builder.
	 */
	public JwtBearerTokenFlow scopes(@Nonnull String... scopes) {
		assertNotNull(scopes, "Scopes must not be null!");
		this.scopes = Arrays.asList(scopes);
		return this;
	}

	/**
	 * Set the Subdomain the token is requested for.
	 *
	 * @param subdomain
	 * 		- the subdomain.
	 * @return this builder.
	 */
	public JwtBearerTokenFlow subdomain(String subdomain) {
		this.subdomain = subdomain;
		return this;
	}

	/**
	 * Adds additional authorization attributes to the request. <br> Clients can use this to request additional
	 * attributes in the 'az_attr' claim of the returned token.
	 *
	 * @param additionalAuthorizationAttributes
	 * 		- the additional attributes.
	 * @return this builder.
	 */
	public JwtBearerTokenFlow attributes(Map<String, String> additionalAuthorizationAttributes) {
		optionalParameters.put(AUTHORITIES, buildAdditionalAuthoritiesJson(additionalAuthorizationAttributes));
		return this;
	}

	/**
	 * Can be used to disable the cache for the flow.
	 *
	 * @param disableCache
	 * 		- disables cache when set to {@code true}.
	 * @return this builder.
	 */
	public JwtBearerTokenFlow disableCache(boolean disableCache) {
		this.disableCache = disableCache;
		return this;
	}

	/**
	 * Can be used to change the format of the returned token.
	 *
	 * @param opaque
	 * 		enables opaque token format when set to {@code true}.
	 * @return this builder.
	 */
	public JwtBearerTokenFlow setOpaqueTokenFormat(boolean opaque) {
		this.opaque = opaque;
		return this;
	}

	/**
	 * Executes this flow against the XSUAA endpoint. As a result the exchanged JWT token is returned.
	 *
	 * @return the JWT instance returned by XSUAA.
	 * @throws IllegalStateException
	 * 		- in case not all mandatory fields of the token flow request have been set.
	 * @throws TokenFlowException
	 * 		- in case of an error during the flow, or when the token cannot be obtained.
	 */
	public OAuth2TokenResponse execute() throws TokenFlowException {
		if (bearerToken == null) {
			throw new IllegalStateException("A bearer token must be set before executing the flow");
		}

		if (opaque) {
			optionalParameters.put(TOKEN_FORMAT, TOKEN_TYPE_OPAQUE);
		} else {
			optionalParameters.remove(TOKEN_FORMAT);
		}

		String scopesParameter = String.join(" ", scopes);
		if (!scopesParameter.isEmpty()) {
			optionalParameters.put(SCOPE, scopesParameter);
		}

		try {
			if (xZid == null) {
				return tokenService
						.retrieveAccessTokenViaJwtBearerTokenGrant(endpointsProvider.getTokenEndpoint(), clientIdentity,
								bearerToken, subdomain, optionalParameters, disableCache);
			}
			return tokenService
					.retrieveAccessTokenViaJwtBearerTokenGrant(endpointsProvider.getTokenEndpoint(), clientIdentity,
							bearerToken, optionalParameters, disableCache, xZid);
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					String.format("Error requesting user token with grant_type '%s': %s",
							OAuth2TokenServiceConstants.GRANT_TYPE_JWT_BEARER, e.getMessage()),
					e);
		}
	}

}
