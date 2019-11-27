package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.xsuaa.jwt.JwtSignatureAlgorithm;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

/**
 * Jwt {@link Token} builder class to generate tokes for testing purposes.
 */
// TODO allow addScopes(String... scopes) in case of XSUAA service
public class JwtGenerator {
	private static final Logger logger = LoggerFactory.getLogger(JwtGenerator.class);

	private static final String JWT_HEADER_ALG = "alg";
	private static final String DOT = ".";

	private final JSONObject jsonHeader = new JSONObject();
	private final JSONObject jsonPayload = new JSONObject();
	private SignatureCalculator signatureCalculator;
	private Service service;

	private JwtSignatureAlgorithm signatureAlgorithm;
	private PrivateKey privateKey;

	private JwtGenerator() {
		// see factory method getInstance()
	}

	public static JwtGenerator getInstance(Service service) {
		return getInstance(service, JwtGenerator::calculateSignature);
	}

	// for testing
	public static JwtGenerator getInstance(Service service, SignatureCalculator signatureCalculator) {
		JwtGenerator instance = new JwtGenerator();
		instance.service = service;
		instance.signatureCalculator = signatureCalculator;
		instance.signatureAlgorithm = JwtSignatureAlgorithm.RS256;
		return instance;
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
	 * Sets the claim with the given name to the given string values.
	 *
	 * @param claimName
	 *            the name of the claim to be set.
	 * @param values
	 *            the string value of the claim to be set.
	 * @return the builder object.
	 */
	public JwtGenerator withClaim(String claimName, Collection<String> values) {
		jsonPayload.put(claimName, values);
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

	/**
	 * Sets the private key that is used to sign the token.
	 *
	 * @param privateKey
	 *            the private key.
	 * @return the builder object.
	 */
	public JwtGenerator withPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
		return this;
	}

	/**
	 * Sets the url which is used to retrieve the verification keys.
	 *
	 * @param jkuUrl
	 *            the url to retrieve the keys
	 * @return the builder object.
	 */
	public JwtGenerator withJku(String jkuUrl) {
		return withHeaderParameter(TokenHeader.JWKS_URL, jkuUrl);
	}

	/**
	 * Sets the keyId value as "kid" header to the jwt.
	 *
	 * @param keyId
	 *            the value of the signed jwt token header "kid"
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator withKeyId(String keyId) {
		return withHeaderParameter(TokenHeader.KEY_ID, keyId);
	}

	/**
	 * Sets the roles as claim "scope" to the jwt. Note that this is specific to
	 * tokens of service type {@link Service#XSUAA}.
	 * 
	 * @throws IllegalArgumentException
	 *             if service is not {@link Service#XSUAA}
	 * @param scopes
	 *            the scopes that should be part of the token
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator withScopes(String... scopes) {
		if (service == Service.XSUAA) {
			withClaim(TokenClaims.XSUAA.SCOPES, Arrays.asList(scopes));
		} else {
			throw new IllegalStateException("Scopes are only supported when service is set to XSUAA!");
		}
		return this;
	}

	/**
	 * Creates and signs the token using the the algorithm set via
	 * {@link #withSignatureAlgorithm(JwtSignatureAlgorithm)} and the given key. By
	 * default{@link JwtSignatureAlgorithm#RS256} is used.
	 *
	 * @return the token.
	 */
	public Token createToken() {
		if (privateKey == null) {
			throw new IllegalStateException("Private key was not set!");
		}
		setHeaderAlgorithmValue();
		String header = base64Encode(jsonHeader.toString().getBytes());
		String payload = base64Encode(jsonPayload.toString().getBytes());
		String headerAndPayload = header + DOT + payload;
		String signature = base64Encode(signatureCalculator
				.calculateSignature(privateKey, signatureAlgorithm, headerAndPayload.getBytes()));

		String token = headerAndPayload + DOT + signature;
		switch (service) {
		case IAS:
			return new IasToken(token);
		case XSUAA:
			return new XsuaaToken(token);
		default:
			throw new IllegalStateException("Unexpected value: " + service);
		}
	}

	private void setHeaderAlgorithmValue() {
		withHeaderParameter(JWT_HEADER_ALG, signatureAlgorithm.value());
	}

	private static byte[] calculateSignature(PrivateKey privateKey, JwtSignatureAlgorithm signatureAlgorithm,
			byte[] dataToSign) {
		try {
			Signature signature = Signature.getInstance(signatureAlgorithm.javaSignature());
			signature.initSign(privateKey);
			signature.update(dataToSign);
			return signature.sign();
		} catch (NoSuchAlgorithmException e) {
			logger.error("Algorithm '{}' not found!", signatureAlgorithm.javaSignature(), e);
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			logger.error("Error creating JWT signature!", e);
			throw new RuntimeException(e);
		} catch (InvalidKeyException e) {
			logger.error("Invalid private key!", e);
			throw new RuntimeException(e);
		}
	}

	private String base64Encode(byte[] bytes) {
		return Base64.getUrlEncoder().encodeToString(bytes);
	}

	interface SignatureCalculator {
		byte[] calculateSignature(PrivateKey privateKey, JwtSignatureAlgorithm algorithm, byte[] dataToSign);
	}

}
