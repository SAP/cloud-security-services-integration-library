package com.sap.cloud.security.javasec.test;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.Base64;

// TODO 14.11.19 c5295400: This is basically a TokenBuilder?
public class JwtGenerator {
	private static final Logger logger = LoggerFactory.getLogger(JwtGenerator.class);

	private static final String JWT_HEADER_ALG = "alg";
	private static final String DOT = ".";

	private final JSONObject jsonHeader = new JSONObject();
	private final JSONObject jsonPayload = new JSONObject();

	private JwtSignatureAlgoritm signatureAlgorithm;

	public JwtGenerator() {
		signatureAlgorithm = JwtSignatureAlgoritm.RS256;
	}

	public JwtGenerator withHeaderParameter(String parameterName, String value) {
		jsonHeader.put(parameterName, value);
		return this;
	}

	public JwtGenerator withClaim(String claimName, String value) {
		jsonPayload.put(claimName, value);
		return this;
	}

	public JwtGenerator withSignatureAlgoritm(JwtSignatureAlgoritm signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
		return this;
	}

	public Token createToken(PrivateKey privateKey) throws InvalidKeyException {
		setHeaderAlgorithmValue();
		String header = base64Encode(jsonHeader.toString().getBytes());
		String payload = base64Encode(jsonPayload.toString().getBytes());
		String headerAndPayload = header + DOT + payload;
		String signature = base64Encode(calculateSignature(headerAndPayload.getBytes(), privateKey));
		return new TokenImpl(headerAndPayload + DOT + signature);
	}

	private void setHeaderAlgorithmValue() {
		withHeaderParameter(JWT_HEADER_ALG, signatureAlgorithm.getJwtAlgorithmHeaderValue());
	}

	private byte[] calculateSignature(byte[] headerAndPayload, PrivateKey privateKey) throws InvalidKeyException {
		try {
			Signature signature = Signature.getInstance(signatureAlgorithm.getJavaSignatureAlgorithmName());
			signature.initSign(privateKey);
			signature.update(headerAndPayload);
			return signature.sign();
		} catch (NoSuchAlgorithmException e) {
			logger.error("Algorithm '{}' not found!", signatureAlgorithm.getJavaSignatureAlgorithmName(), e);
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
