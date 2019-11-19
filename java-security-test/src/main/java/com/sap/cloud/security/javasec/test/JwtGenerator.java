package com.sap.cloud.security.javasec.test;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import org.json.JSONObject;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Base64;

// TODO 14.11.19 c5295400: This is basically a TokenBuilder?
public class JwtGenerator {

	private static final String JWT_HEADER_ALG = "alg";
	private static final String DOT = ".";

	private final JSONObject jsonHeader = new JSONObject();
	private final JSONObject jsonPayload = new JSONObject();

	private JwtSignatureAlgoritm jwtSignatureAlgoritm;

	public JwtGenerator() {
		jwtSignatureAlgoritm = JwtSignatureAlgoritm.RS256;
	}

	public JwtGenerator withHeaderParameter(String parameterName, String value) {
		jsonHeader.put(parameterName, value);
		return this;
	}

	public JwtGenerator withClaim(String claimName, String value) {
		jsonPayload.put(claimName, value);
		return this;
	}

	public JwtGenerator withSignatureAlgoritm(JwtSignatureAlgoritm jwtSignatureAlgoritm) {
		this.jwtSignatureAlgoritm = jwtSignatureAlgoritm;
		return this;
	}

	public Token createToken(PrivateKey privateKey)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		setHeaderAlgorithmValue();
		String header = base64Encode(jsonHeader.toString().getBytes());
		String payload = base64Encode(jsonPayload.toString().getBytes());
		String headerAndPayload = header + DOT + payload;
		String signature = base64Encode(calculateSignature(headerAndPayload.getBytes(), privateKey));
		return new TokenImpl(headerAndPayload + DOT + signature);
	}

	private void setHeaderAlgorithmValue() {
		withHeaderParameter(JWT_HEADER_ALG, jwtSignatureAlgoritm.getJwtAlgorithmHeaderValue());
	}

	private byte[] calculateSignature(byte[] headerAndPayload, PrivateKey privateKey)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		java.security.Signature signature = java.security.Signature
				.getInstance(this.jwtSignatureAlgoritm.getJavaSignatureAlgorithmName());
		signature.initSign(privateKey);
		signature.update(headerAndPayload);
		return signature.sign();
	}

	private String base64Encode(byte[] bytes) {
		return Base64.getUrlEncoder().encodeToString(bytes);
	}

}
