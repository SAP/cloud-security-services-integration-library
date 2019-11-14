package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import org.json.JSONObject;

import java.security.*;
import java.util.Base64;

// TODO 14.11.19 c5295400: This is basically a TokenBuilder?
public class JwtGenerator {

	private final JSONObject jsonHeader = new JSONObject();
	private final JSONObject jsonPayload = new JSONObject();
	private final PrivateKey privateKey;

	public JwtGenerator(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public JwtGenerator withAlgorithm(String algorithm) {
		return withHeaderParameter(JwtConstants.Header.ALG, algorithm);
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
		return new TokenImpl(header + "." + payload + "." + calculateSignature(header, payload));
	}

	private String calculateSignature(String header, String payload)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		byte[] bytes = (header + "." + payload).getBytes();
		return calculateSignature(bytes);
	}

	private String calculateSignature(byte[] bytes)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(bytes);
		return base64Encode(signature.sign());
	}

	private String base64Encode(byte[] bytes) {
		return Base64.getUrlEncoder().encodeToString(bytes);
	}
}
