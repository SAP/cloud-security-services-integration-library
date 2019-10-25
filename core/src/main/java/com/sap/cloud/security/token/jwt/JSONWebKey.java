package com.sap.cloud.security.token.jwt;

import javax.annotation.Nullable;

import java.security.PublicKey;


/**
 * see also JSON Web Key (JWK) specification:
 * https://tools.ietf.org/html/rfc7517
 */
public interface JSONWebKey {
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
	 * @returns the algorithm the JWT is signed.
	 */
	@Nullable
	public String getAlgorithm();

	/**
	 * Returns the key type, e.g. "RSA".
	 * @returns the key type.
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
	 * Returns the PEM encoded public key.
	 * Starting with {@code -----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEF...}
	 * @return the public key.
	 */
	public String getPublicKeyPemEncoded();

	/**
	 * Returns the public key.
	 *
	 * @return the public key.
	 */
	public PublicKey getPublicKey();
}
