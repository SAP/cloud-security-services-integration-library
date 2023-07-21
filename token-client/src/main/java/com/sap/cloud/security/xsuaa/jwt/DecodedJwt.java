/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.jwt;

import java.io.Serializable;

/**
 * A Jwt token consists of three parts, separated by ".":
 * header.payload.signature
 * <p>
 * Use {@code Base64JwtDecoder.getInstance().decode(token)} to get a
 * {@link DecodedJwt} instance.
 */

public interface DecodedJwt extends Serializable {

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
	String getPayload();

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
