package com.sap.cloud.security.test;

import static com.sap.cloud.security.token.TokenClaims.AUDIENCE;
import static com.sap.cloud.security.token.TokenHeader.*;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.validators.JwtSignatureAlgorithm;
import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Jwt {@link Token} builder class to generate tokes for testing purposes.
 */
public class JwtGenerator {
	public static final Instant NO_EXPIRE_DATE = new GregorianCalendar(2190, 11, 31).getTime().toInstant();

	private static final Logger LOGGER = LoggerFactory.getLogger(JwtGenerator.class);
	private static final String DEFAULT_JWKS_URL = "http://localhost";
	private static final String DEFAULT_KEY_ID = "default-kid";
	private static final char DOT = '.';

	private final JSONObject jsonHeader = new JSONObject();
	private final JSONObject jsonPayload = new JSONObject();
	private final Set<String> unsupportedClaims = Arrays.asList(AUDIENCE).stream().collect(Collectors.toSet());

	private SignatureCalculator signatureCalculator;
	private Service service;

	private JwtSignatureAlgorithm signatureAlgorithm;
	private PrivateKey privateKey;

	private JwtGenerator() {
		// see factory method getInstance()
	}

	public static JwtGenerator getInstance(Service service, String clientId) {
		return getInstance(service, JwtGenerator::calculateSignature, clientId);
	}

	// for testing
	static JwtGenerator getInstance(Service service, SignatureCalculator signatureCalculator, String clientId) {
		JwtGenerator instance = new JwtGenerator();
		instance.service = service;
		instance.signatureCalculator = signatureCalculator;
		instance.signatureAlgorithm = JwtSignatureAlgorithm.RS256;
		setTokenDefaults(clientId, instance);
		return instance;
	}

	private static void setTokenDefaults(String clientId, JwtGenerator instance) {
		instance.withHeaderParameter(ALGORITHM, instance.signatureAlgorithm.value());
		instance.withHeaderParameter(KEY_ID, DEFAULT_KEY_ID);
		instance.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, clientId);
		instance.withExpiration(NO_EXPIRE_DATE);
		if (instance.service == Service.XSUAA) {
			instance.withHeaderParameter(JWKS_URL, DEFAULT_JWKS_URL);
		}
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
	public JwtGenerator withClaimValue(String claimName, String value) {
		assertClaimIsSupported(claimName);
		jsonPayload.put(claimName, value);
		return this;
	}

	/**
	 * Sets the claim with the given name to the given string value.
	 *
	 * @param claimName
	 *            the name of the claim to be set.
	 * @param object
	 *            the string value of the claim to be set.
	 * @return the builder object.
	 * @throws JsonParsingException
	 *             if the given object does not contain valid json.
	 */
	public JwtGenerator withClaimValue(String claimName, JsonObject object) {
		assertClaimIsSupported(claimName);
		try {
			jsonPayload.put(claimName, new JSONObject(object.asJsonString()));
		} catch (JSONException e) {
			throw new JsonParsingException(e.getMessage());
		}
		return this;
	}

	/**
	 * Sets the claim with the given name to the given string values.
	 *
	 * @param claimName
	 *            the name of the claim to be set.
	 * @param values
	 *            the string values of the claims to be set.
	 * @return the builder object.
	 */
	public JwtGenerator withClaimValues(String claimName, String... values) {
		assertClaimIsSupported(claimName);
		jsonPayload.put(claimName, values);
		return this;
	}

	/**
	 * This method will fill the token with all the claims that are defined inside
	 * the given file. The file must contain a valid json object.
	 *
	 * @throws JsonParsingException
	 *             if the file does not contain a valid json object.
	 * @throws IOException
	 *             when the file cannot be read or does not exist.
	 * @param claimsJsonResource
	 *            the resource path to the file containing the claims in json format, e.g. "/claims.json"
	 * @return the builder object.
	 */
	public JwtGenerator withClaimsFromFile(String claimsJsonResource) throws IOException {
		String claimsJson = IOUtils.resourceToString(claimsJsonResource, StandardCharsets.UTF_8);
		JSONObject claimsAsJsonObject;
		try {
			claimsAsJsonObject = new JSONObject(claimsJson);
		} catch (JSONException e) {
			throw new JsonParsingException(e.getMessage());
		}
		for (String key : claimsAsJsonObject.keySet()) {
			Object value = claimsAsJsonObject.get(key);
			jsonPayload.put(key, value);
		}
		return this;
	}

	private void assertClaimIsSupported(String claimName) {
		if (unsupportedClaims.contains(claimName)) {
			throw new UnsupportedOperationException("generic method for claim " + claimName + " is not supported");
		}
	}

	/**
	 * Sets the expiration claim (exp) of the token to the given moment in time.
	 *
	 * @param expiration
	 *            the moment in time when the token will be expired.
	 * @return the builder object.
	 */
	public JwtGenerator withExpiration(@Nonnull Instant expiration) {
		jsonPayload.put(TokenClaims.EXPIRATION, expiration.getEpochSecond());
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
		if (signatureAlgorithm != JwtSignatureAlgorithm.RS256) {
			throw new UnsupportedOperationException(signatureAlgorithm + " is not supported yet");
		}
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
	 * Sets the roles as claim "scope" to the jwt. Note that this is specific to
	 * tokens of service type {@link Service#XSUAA}.
	 *
	 * @param scopes
	 *            the scopes that should be part of the token
	 * @return the JwtGenerator itself
	 * @throws IllegalArgumentException
	 *             if service is not {@link Service#XSUAA}
	 */
	public JwtGenerator withScopes(String... scopes) {
		if (service == Service.XSUAA) {
			withClaimValues(TokenClaims.XSUAA.SCOPES, scopes);
		} else {
			throw new UnsupportedOperationException("Scopes are not supported for service " + service);
		}
		return this;
	}

	/**
	 * Builds and signs the token using the the algorithm set via
	 * {@link #withSignatureAlgorithm(JwtSignatureAlgorithm)} and the given key. By
	 * default{@link JwtSignatureAlgorithm#RS256} is used.
	 *
	 * @return the token.
	 */
	public Token createToken() {
		if (privateKey == null) {
			throw new IllegalStateException("Private key was not set!");
		}

		createAudienceClaim();

		switch (service) {
		case IAS:
			return new SapIdToken(createTokenAsString());
		case XSUAA:
			return new XsuaaToken(createTokenAsString());
		default:
			throw new UnsupportedOperationException("Identity Service " + service + " is not supported.");
		}
	}

	private void createAudienceClaim() {
		if (service == Service.IAS) {
			jsonPayload.put(AUDIENCE, jsonPayload.getString(TokenClaims.XSUAA.CLIENT_ID));
		} else {
			jsonPayload.put(AUDIENCE, Arrays.asList(jsonPayload.getString(TokenClaims.XSUAA.CLIENT_ID)));
		}
	}

	private String createTokenAsString() {
		String header = base64Encode(jsonHeader.toString().getBytes());
		String payload = base64Encode(jsonPayload.toString().getBytes());
		String headerAndPayload = header + DOT + payload;
		String signature = calculateSignature(headerAndPayload);
		return headerAndPayload + DOT + signature;
	}

	private static byte[] calculateSignature(PrivateKey privateKey, JwtSignatureAlgorithm signatureAlgorithm,
			byte[] dataToSign) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
		Signature signature = Signature.getInstance(signatureAlgorithm.javaSignature());
		signature.initSign(privateKey);
		signature.update(dataToSign);
		return signature.sign();
	}

	private String calculateSignature(String headerAndPayload) {
		try {
			return base64Encode(signatureCalculator
					.calculateSignature(privateKey, signatureAlgorithm, headerAndPayload.getBytes()));
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Algorithm '{}' not found.", signatureAlgorithm.javaSignature());
			throw new UnsupportedOperationException(e);
		} catch (SignatureException e) {
			LOGGER.error("Error creating JWT signature.");
			throw new UnsupportedOperationException(e);
		} catch (InvalidKeyException e) {
			LOGGER.error("Invalid private key.");
			throw new UnsupportedOperationException(e);
		}
	}

	private String base64Encode(byte[] bytes) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	interface SignatureCalculator {
		byte[] calculateSignature(PrivateKey privateKey, JwtSignatureAlgorithm algorithm, byte[] dataToSign)
				throws InvalidKeyException, SignatureException, NoSuchAlgorithmException;
	}

}
