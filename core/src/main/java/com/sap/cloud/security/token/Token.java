package com.sap.cloud.security.token;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public interface Token {

	/**
	 * Returns the header vale as string for the given header name.
	 *
	 * @param headerName
	 *            the name of the header parameter.
	 * @return the value for the given header name.
	 */
	@Nullable
	String getHeaderValue(@Nonnull String headerName);

	/**
	 * Returns the value as string for the given claim.
	 *
	 * @param claimName
	 *            the name of the claim.
	 * @return the corresponding string value of the given claim.
	 */
	@Nullable
	String getClaimAsString(@Nonnull String claimName);

	boolean containsClaim(@Nonnull String claimName);

	@Nullable
	Map<String, Object> getClaimAsMap(@Nonnull String claimName);

	@Nullable
	List<String> getClaimAsStringList(@Nonnull String claimName);

	/**
	 * Returns list of scopes.
	 * @return all scopes
	 */
	@Nullable
	List<String> getScopes();

	/**
	 * Returns the moment in time when the token will be expired.
	 *
	 * @return the expiration point in time if present.
	 */
	@Nullable
	Instant getExpiration();

	/**
	 * Get the original encoded access token.
	 *
	 * <p>
	 * Never expose this token via log or via HTTP.
	 *
	 * @return jwt token
	 */
	String getEncodedToken();

}
