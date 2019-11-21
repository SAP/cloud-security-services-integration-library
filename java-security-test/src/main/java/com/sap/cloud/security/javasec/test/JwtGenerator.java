package com.sap.cloud.security.javasec.test;

import com.sap.cloud.security.token.AbstractToken;
import com.sap.cloud.security.token.JwtSignatureAlgorithm;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.UserPrincipal;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.Base64;

/**
 * Jwt {@link Token} builder class to generate tokes for testing purposes.
 */
public class JwtGenerator {
	private static final Logger logger = LoggerFactory.getLogger(JwtGenerator.class);

	private static final String JWT_HEADER_ALG = "alg";
	private static final String DOT = ".";

	private final JSONObject jsonHeader = new JSONObject();
	private final JSONObject jsonPayload = new JSONObject();

	private JwtSignatureAlgorithm signatureAlgorithm;

	public JwtGenerator() {
		signatureAlgorithm = JwtSignatureAlgorithm.RS256;
	}

	/**
	 * Sets the header parameter with the given name to the given string value.
	 *
	 * @param parameterName
	 *            the name of the header parameter to be set.
	 * @param value
	 *            the string value of the header parameter to be set.
	 * @return the builder object.
	 */
	public JwtGenerator withHeaderParameter(String parameterName, String value) {
		jsonHeader.put(parameterName, value);
		return this;
	}

	/**
	 * Sets the claim with the given name to the given string value.
	 *
	 * @param claimName
	 *            the name of the claim to be set.
	 * @param value
	 *            the string value of the claim to be set.
	 * @return the builder object.
	 */
	public JwtGenerator withClaim(String claimName, String value) {
		jsonPayload.put(claimName, value);
		return this;
	}

	/**
	 * Sets the signature algorithm that is used to create the signature of the
	 * token.
	 *
	 * @param signatureAlgorithm
	 *            the signature algorithm.
	 * @return the builder object.
	 */
	public JwtGenerator withSignatureAlgorithm(JwtSignatureAlgorithm signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
		return this;
	}

	// TODO: createToken without parameter should use the predefined /resources/privateKey.

	/**
	 * Creates and signs the token using the the algorithm set via
	 * {@link #withSignatureAlgorithm(JwtSignatureAlgorithm)} and the given key. By
	 * default{@link JwtSignatureAlgorithm#RS256} is used.
	 *
	 * @param privateKey
	 *            the private key that is used to sign the token.
	 * @return the token.
	 * @throws InvalidKeyException
	 *             if the key cannot be used for creating a signature with the
	 *             current JwtSignatureAlgorithm.
	 */
	public Token createToken(PrivateKey privateKey) throws InvalidKeyException {
		setHeaderAlgorithmValue();
		String header = base64Encode(jsonHeader.toString().getBytes());
		String payload = base64Encode(jsonPayload.toString().getBytes());
		String headerAndPayload = header + DOT + payload;
		String signature = base64Encode(calculateSignature(headerAndPayload.getBytes(), privateKey));
		return new AbstractToken(headerAndPayload + DOT + signature) {
			@Override public UserPrincipal getPrincipal() {
				return null;
			}
		};
	}

	private void setHeaderAlgorithmValue() {
		withHeaderParameter(JWT_HEADER_ALG, signatureAlgorithm.asJwt());
	}

	private byte[] calculateSignature(byte[] headerAndPayload, PrivateKey privateKey) throws InvalidKeyException {
		try {
			Signature signature = Signature.getInstance(signatureAlgorithm.asJava());
			signature.initSign(privateKey);
			signature.update(headerAndPayload);
			return signature.sign();
		} catch (NoSuchAlgorithmException e) {
			logger.error("Algorithm '{}' not found!", signatureAlgorithm.asJava(), e);
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			logger.error("Error creating JWT signature!", e);
			throw new RuntimeException(e);
		}
	}

	private String base64Encode(byte[] bytes) {
		return Base64.getUrlEncoder().encodeToString(bytes);
	}

}
