package com.sap.cloud.security.token;

import com.sap.cloud.security.json.JsonParsingException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.Principal;
import java.time.Instant;
import java.util.List;

public interface Token {

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
	 * Checks whether the token contains a given claim.
	 *
	 * @param claimName
	 *            the name of the claim as defined here {@link TokenClaims}.
	 * @return true when the claim with the given name is found.
	 */
	boolean containsClaim(@Nonnull String claimName);

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
	 * not found, it will return null. If the given calim is not a list of strings,
	 * it will throw a {@link JsonParsingException}.
	 * 
	 * @param claimName
	 *            the name of the claim as defined here {@link TokenClaims}.
	 * @return the data of the given claim as a list of strings.
	 */
	@Nullable
	List<String> getClaimAsStringList(@Nonnull String claimName);

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
	 * @return the encoded token.
	 */
	String getAccessToken();


	Principal getPrincipal();
}
