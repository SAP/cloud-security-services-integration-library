/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.Serializable;
import java.security.Principal;
import java.security.ProviderException;
import java.time.Instant;
import java.util.*;

import static com.sap.cloud.security.token.TokenClaims.*;

/**
 * Represents a JSON Web Token (JWT).
 */
public interface Token extends Serializable {

	@SuppressWarnings("unchecked")
	List<TokenFactory> services = new ArrayList() {
		{
			ServiceLoader.load(TokenFactory.class).forEach(this::add);
			LoggerFactory.getLogger(Token.class).info("loaded TokenFactory service providers: {}", this);
		}
	};

	String DEFAULT_TOKEN_FACTORY = "com.sap.cloud.security.servlet.HybridTokenFactory";

	/**
	 * Creates a token instance based on TokenFactory implementation.
	 *
	 * @param jwt
	 *            encoded JWT token
	 * @return token instance
	 */
	static Token create(String jwt) {
		if (services.isEmpty()) {
			throw new ProviderNotFoundException("No TokenFactory implementation found in the classpath");
		}
		if (services.size() > 2) {
			throw new ProviderException(
					"More than 1 Custom TokenFactory service provider found. There should be only one");
		}
		if (services.size() == 2) {
			return services.stream()
					.filter(tokenFactory -> !tokenFactory.getClass().getName()
							.equals(DEFAULT_TOKEN_FACTORY))
					.findFirst().get().create(jwt);
		}
		return services.get(0).create(jwt);
	}

	/**
	 * Returns the header parameter value as string for the given header parameter
	 * name.
	 *
	 * @param headerName
	 *            the name of the header parameter as defined here
	 *            {@link TokenHeader}
	 * @return the value for the given header name or null, if the header is not
	 *         provided.
	 */
	@Nullable
	String getHeaderParameterAsString(@Nonnull String headerName);

	/**
	 * Checks whether the token contains a given header parameter.
	 *
	 * @param headerName
	 *            the name of the header parameter as defined here
	 *            {@link TokenHeader}
	 * @return true when the given header name is found.
	 */
	boolean hasHeaderParameter(@Nonnull String headerName);

	/**
	 * Checks whether the token contains a given claim.
	 *
	 * @param claimName
	 *            the name of the claim as defined here {@link TokenClaims}.
	 * @return true when the claim with the given name is found.
	 */
	boolean hasClaim(@Nonnull String claimName);

	/**
	 * Extracts the value as string for the given claim. If the claim is not found,
	 * it will return null. If the given claim is not a string, it will throw a
	 * {@link JsonParsingException}.
	 *
	 * @param claimName
	 *            the name of the claim as defined here {@link TokenClaims}.
	 * @return the corresponding string value of the given claim or null.
	 *
	 * @throws JsonParsingException
	 *             if the json object identified by the given claim is not a string.
	 */
	@Nullable
	String getClaimAsString(@Nonnull String claimName);

	/**
	 * Extracts the value as a list of strings for the given claim. If the claim is
	 * not found, it will return null. If the given claim is not a list of strings,
	 * it will throw a {@link JsonParsingException}.
	 *
	 * @param claimName
	 *            the name of the claim as defined here {@link TokenClaims}.
	 * @return the data of the given claim as a list of strings or an empty list.
	 */
	@Nonnull
	List<String> getClaimAsStringList(@Nonnull String claimName);

	/**
	 * Extracts the value of the given as a JsonObject. Use this to extract nested
	 * objects. If the claim is not found, it will return null. If the vale for the
	 * given claim is not an object, it will throw a {@link JsonParsingException}.
	 *
	 * @param claimName
	 *            the name of the claim for which the object should be extracted.
	 * @return the corresponding {@link JsonObject} for the given claim.
	 */
	@Nullable
	JsonObject getClaimAsJsonObject(@Nonnull String claimName);

	/**
	 * Returns the moment in time when the token will be expired.
	 *
	 * @return the expiration point in time if present.
	 */
	@Nullable
	Instant getExpiration();

	/**
	 * Returns true if the token is expired.
	 *
	 * @return true if the token is expired.
	 */
	boolean isExpired();

	/**
	 * Returns the moment in time before which the token must not be accepted.
	 *
	 * @return the not before point in time if present.
	 */
	@Nullable
	Instant getNotBefore();

	/**
	 * Get the encoded jwt token, e.g. for token forwarding to another app.
	 *
	 * <p>
	 * Never expose this token via log or via HTTP.
	 *
	 * @return the encoded token.
	 */
	String getTokenValue();

	/**
	 * Returns a principal, which can be used to represent any entity, such as an
	 * individual, a corporation, and a login id.
	 *
	 * @return the principal or null if not yet implemented.
	 */
	Principal getPrincipal();

	/**
	 * Returns the identity service, the token is issued by.
	 *
	 * @return the service.
	 */
	Service getService();

	/**
	 * Returns the (empty) list of audiences the token is issued for. <br>
	 *
	 * @return the audiences.
	 **/
	default Set<String> getAudiences() {
		return new LinkedHashSet<>(getClaimAsStringList(AUDIENCE));
	}

	/**
	 * @deprecated use {@link Token#getAppTid()} instead
	 */
	@Deprecated
	String getZoneId();

	/**
	 * Returns the app tenant identifier, which can be used as tenant discriminator
	 * (tenant guid).
	 *
	 * @return the unique application tenant identifier.
	 */
	default String getAppTid(){
		return hasClaim(SAP_GLOBAL_APP_TID) ? getClaimAsString(SAP_GLOBAL_APP_TID) : getClaimAsString(SAP_GLOBAL_ZONE_ID);
	}

	/**
	 * Returns the OAuth2 client identifier of the authentication token if present.
	 * Following OpenID Connect 1.0 standard specifications, client identifier is
	 * obtained from "azp" claim if present or when "azp" is not present from "aud"
	 * claim, but only in case there is one audience.
	 *
	 * @see <a href=
	 *      "https://openid.net/specs/openid-connect-core-1_0.html">https://openid.net/specs/openid-connect-core-1_0.html</a>
	 *
	 * @return the OAuth client ID.
	 */
	default String getClientId() {
		String clientId = getClaimAsString(AUTHORIZATION_PARTY);
		if (clientId == null || clientId.trim().isEmpty()) {
			Set<String> audiences = getAudiences();
			if (audiences.size() == 1) {
				return audiences.stream().findFirst().get();
			}
			throw new InvalidTokenException("Couldn't get client id. Invalid authorized party or audience claims.");
		} else {
			return clientId;
		}
	}

	/**
	 * Returns the identifier for the Issuer of the token. Its a URL that contains
	 * scheme, host, and optionally, port number and path components but no query or
	 * fragment components. This one is validated in the {@code JwtIssuerValidator}
	 * and used as base url to discover jwks_uri endpoint for downloading the token
	 * keys.
	 *
	 * @return the issuer.
	 */
	default String getIssuer() {
		return getClaimAsString(ISSUER);
	}

	/**
	 * Returns the grant type of the jwt token. <br>
	 *
	 * @return the grant type
	 **/
	@Nullable
	default GrantType getGrantType() {
		return GrantType.from(getClaimAsString(TokenClaims.XSUAA.GRANT_TYPE));
	}

	/**
	 * Returns the header(s).
	 *
	 * @return a {@code Map} of the header(s)
	 */
	default Map<String, Object> getHeaders() {
		return Collections.emptyMap();
	}

	/**
	 * Returns the jwt claim set.
	 *
	 * @return a {@code Map} of the jwt claim set
	 */
	default Map<String, Object> getClaims() {
		return Collections.emptyMap();
	}

	/**
	 * Returns the String value of a claim attribute. <br>
	 * <code>
	 *     "claimName": {
	 *         "attributeName": "attributeValueAsString"
	 *     },
	 *     </code><br>
	 * <br>
	 * Example: <br>
	 * <code>
	 *     import static com.sap.cloud.security.token.TokenClaims.XSUAA.*;
	 *     token.getAttributeFromClaimAsString(EXTERNAL_ATTRIBUTE, EXTERNAL_ATTRIBUTE_SUBACCOUNTID);
	 *     </code>
	 *
	 * @return the String value of a claim attribute or null if claim or its
	 *         attribute does not exist.
	 **/
	@Nullable
	default String getAttributeFromClaimAsString(String claimName, String attributeName) {
		return Optional.ofNullable(getClaimAsJsonObject(claimName))
				.map(claim -> claim.getAsString(attributeName))
				.orElse(null);
	}

	/**
	 * Returns the String list of a claim attribute. <br>
	 * <code>
	 *     "claimName": {
	 *         "attributeName": ["attributeValueAsString", "attributeValue2AsString"]
	 *     },
	 *     </code><br>
	 * <br>
	 * Example: <br>
	 * <code>
	 *     import static com.sap.cloud.security.token.TokenClaims.XSUAA.*;
	 *
	 *     token.getAttributeFromClaimAsString(XS_USER_ATTRIBUTES, "custom_role");
	 *     </code>
	 *
	 * @return the list of String values of a claim attribute or empty List if claim
	 *         or its attribute does not exist.
	 **/
	default List<String> getAttributeFromClaimAsStringList(String claimName, String attributeName) {
		JsonObject claimAsJsonObject = getClaimAsJsonObject(claimName);
		return Optional.ofNullable(claimAsJsonObject)
				.map(jsonObject -> jsonObject.getAsList(attributeName, String.class))
				.orElse(Collections.emptyList());
	}
}
