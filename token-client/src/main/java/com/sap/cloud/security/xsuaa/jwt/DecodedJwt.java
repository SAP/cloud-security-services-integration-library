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
	 * Get the base64 decoded payload of the jwt as UTF-8 String.
	 *
	 * @return the decoded payload.
	 */
	@Nullable
	String getHeaderValue(@Nonnull String name);

	String getPayload();

	/**
	 * Get the encoded signature of the jwt.
	 *
	 * @return the decoded signature.
	 */
	@Nullable // TODO getClaimByName?
	String getPayloadValue(@Nonnull String name);

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
