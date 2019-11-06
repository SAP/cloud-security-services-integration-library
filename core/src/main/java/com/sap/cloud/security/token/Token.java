package com.sap.cloud.security.token;

import com.sap.cloud.security.json.JsonParsingException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.Instant;
import java.util.List;

public interface Token {

	/**
	 * Returns the header vale as string for the given header name.
	 *
	 * @param headerName
	 *            the name of the header parameter.
	 * @return the value for the given header name.
	 */
	@Nullable
	String getHeaderValueAsString(@Nonnull String headerName);

	/**
	 * @param claimName
	 *            the name of the claim.
	 * @return true when the claim with the given name is found.
	 */
	boolean containsClaim(@Nonnull String claimName);

	/**
	 * Extracts the value as string for the given claim. If the claim is not found,
	 * it will return null. If the given claim is not a string, it will throw a
	 * {@link JsonParsingException}.
	 * 
	 * @param claimName
	 *            the name of the claim.
	 * @return the corresponding string value of the given claim or null.
	 *
	 * @throws JsonParsingException
	 *             if the json object identified by the given claim is not a string.
	 */
	@Nullable
	String getClaimAsString(@Nonnull String claimName);

	/**
	 * Extracts the value as a list of strings for the given claim. If the claim is
	 * not found, it will return null. If the given calim is not a list of strings,
	 * it will throw a {@link JsonParsingException}.
	 * 
	 * @param claimName
	 *            the name of the claim.
	 * @return the data of the given claim as a list of strings.
	 */
	@Nullable
	List<String> getClaimAsStringList(@Nonnull String claimName);

	/**
	 * Returns list of scopes.
	 * 
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
	 * Returns the moment in time before which the token must not be accepted.
	 *
	 * @return the not before point in time if present.
	 */
	@Nullable
	Instant getNotBefore();

	/**
	 * Get the original encoded access token.
	 *
	 * <p>
	 * Never expose this token via log or via HTTP.
	 *
	 * @return jwt token
	 */
	String getAppToken();

}
