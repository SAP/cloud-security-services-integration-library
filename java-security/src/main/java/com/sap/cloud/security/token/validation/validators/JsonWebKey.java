/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import javax.annotation.Nullable;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * See also JSON Web Key (JWK) specification:
 * <a href="https://tools.ietf.org/html/rfc7517">tools.ietf.org/html/rfc7517"</a>
 */
interface JsonWebKey {
	@java.lang.SuppressWarnings("squid:S1214")
	String DEFAULT_KEY_ID = "default-kid";

	/**
	 * Returns the key algorithm a JWT is/can be signed with, e.g.
	 * {@link JwtSignatureAlgorithm#RS256}.
	 * 
	 * @return the key algorithm.
	 */
	JwtSignatureAlgorithm getKeyAlgorithm();

	/**
	 * Returns the key id. This is used, for instance, to choose among a set of keys
	 * within a JWK Set during key rollover.
	 * 
	 * @return unique key identifier.
	 */
	@Nullable
	String getId();

	/**
	 * Returns the public key representation.
	 * 
	 * @return the public key.
	 * @throws InvalidKeySpecException
	 *             in case the a PublicKey can not be created for this JSON web key.
	 * @throws NoSuchAlgorithmException
	 *             in case the algorithm specified as part of the JSON web key is
	 *             not supported.
	 */
	@Nullable
	PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException;

}
