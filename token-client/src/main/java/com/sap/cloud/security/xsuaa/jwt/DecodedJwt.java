package com.sap.cloud.security.xsuaa.jwt;

/**
 * A Jwt token consists of three parts, separated by ".":
 * header.payload.signature
 */
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface DecodedJwt {

	/**
	 * Get the base64 decoded header of the jwt as UTF-8 String.
	 *
	 * @return the decoded header.
	 */
	String getHeader();

	/**
	 * Returns the header vale as string for the given header name.
	 * @param headerName the name of the header parameter.
	 * @return the value for the given header name.
	 */
	@Nullable
	String getHeaderValue(@Nonnull String headerName);

	/**
	 * Get the base64 decoded payload of the jwt as UTF-8 String.
	 *
	 * @return the decoded payload.
	 */
	String getPayload();

	/**
	 * Returns the value as string for the given claim.
	 * @param claimName the name of the claim.
	 * @return the corresponding value of the given claim.
	 */
	@Nullable
	String getClaim(@Nonnull String claimName);

	/**
	 * Get the encoded signature of the jwt.
	 *
	 * @return the decoded signature.
	 */
	String getSignature();

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
