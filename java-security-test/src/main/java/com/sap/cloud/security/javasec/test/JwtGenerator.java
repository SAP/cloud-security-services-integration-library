package com.sap.cloud.security.javasec.test;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import org.json.JSONObject;

import java.security.*;
import java.util.Base64;

// TODO 14.11.19 c5295400: This is basically a TokenBuilder?
public class JwtGenerator {

	private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
	private static final String HEADER_PARAMETER_ALG = "alg";

	private static final String DOT = ".";
	private final JSONObject jsonHeader = new JSONObject();
	private final JSONObject jsonPayload = new JSONObject();
	private final PrivateKey privateKey;
	public static final String ALG = "alg";

	public JwtGenerator(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public JwtGenerator withAlgorithm(String algorithm) {
		return withHeaderParameter(HEADER_PARAMETER_ALG, algorithm);
	}

	public JwtGenerator withHeaderParameter(String parameterName, String value) {
		jsonHeader.put(parameterName, value);
		return this;
	}

	public JwtGenerator withClaim(String claimName, String value) {
		jsonPayload.put(claimName, value);
		return this;
	}

	public Token createToken() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		String header = base64Encode(jsonHeader.toString().getBytes());
		String payload = base64Encode(jsonPayload.toString().getBytes());
		String headerAndPayload = header + DOT + payload;
		String signature = base64Encode(calculateSignature(headerAndPayload.getBytes()));
		return new TokenImpl(headerAndPayload + DOT + signature);
	}

	private byte[] calculateSignature(byte[] bytes)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(privateKey);
		signature.update(bytes);
		return signature.sign();
	}

	private String base64Encode(byte[] bytes) {
		return Base64.getUrlEncoder().encodeToString(bytes);
	}
}
