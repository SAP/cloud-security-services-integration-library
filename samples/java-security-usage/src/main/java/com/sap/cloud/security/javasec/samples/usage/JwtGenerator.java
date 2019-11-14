package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import org.json.JSONObject;

import java.security.*;
import java.util.Base64;

public class JwtGenerator {

	public static final String PAYLOAD = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
	private final JSONObject jsonHeader = new JSONObject();
	private final PrivateKey privateKey;

	public JwtGenerator(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public JwtGenerator withAlgorithm(String algorithm) {
		jsonHeader.put(JwtConstants.Header.ALG, algorithm);
		return this;
	}

	public Token createToken() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		String header = base64Encode(jsonHeader.toString().getBytes());
		return new TokenImpl(header + "." + PAYLOAD + "." + calculateSignature(header, PAYLOAD));
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
