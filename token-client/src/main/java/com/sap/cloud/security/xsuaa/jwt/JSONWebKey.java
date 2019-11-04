package com.sap.cloud.security.xsuaa.jwt;

import javax.annotation.Nullable;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * see also JSON Web Key (JWK) specification:
 * https://tools.ietf.org/html/rfc7517
 */
public interface JSONWebKey {
	static final String DEFAULT_KEY_ID = "default-kid";

	/**
	 * https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1
	 */
	public enum Type {
		RSA("RSA"), APPLICATION_FORM_URLENCODED("application/x-www-form-urlencoded");

		final String value;

		Type(String value) {
			this.value = value;
		}

		public String value() {
			return value;
		}
	}

	/**
	 * Returns a JSON Web e.g. RS256, see also specification here: https://tools.ietf.org/html/rfc7518
	 * @return the algorithm the JWT is signed.
	 */
	public String getAlgorithm();

	/**
	 * Returns the key type, e.g. "RSA".
	 * @return the key type.
	 */
	@Nullable
	public Type getType();

	/**
	 * Returns the key id. This is used, for instance,
	 * to choose among a set of keys within a JWK Set during key rollover.
	 * @return unique key identifier.
	 */
	@Nullable
	public String getId();

	/**
	 * Returns the public key.
	 * @return the public key.
	 */
	@Nullable
	public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException;

}
