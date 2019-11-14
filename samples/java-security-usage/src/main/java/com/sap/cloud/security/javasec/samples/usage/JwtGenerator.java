package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.Base64;

public class JwtGenerator {
	private static final Logger logger = LoggerFactory.getLogger(JwtGenerator.class);

	private final JSONObject jsonHeader = new JSONObject();
	private final PrivateKey privateKey;
	public static final String PAYLOAD = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";

	public JwtGenerator(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public Token createToken(String signature) {
		byte[] bytes = jsonHeader.toString().getBytes();
		String header = base64Encode(bytes);
		return new TokenImpl(header + "." + PAYLOAD + "." + signature);
	}

	public JwtGenerator withAlgorithm(String algorithm) {
		jsonHeader.put(JwtConstants.Header.ALG, algorithm);
		return this;
	}

	public Token createTokenWithSignature() throws  NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		String header = new String(Base64.getEncoder().encode(jsonHeader.toString().getBytes()));
		return createToken(calculateSignature(header, PAYLOAD));
	}

	private String calculateSignature(String header, String payload) throws  NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		byte[] bytes = (header + "." + payload).getBytes();
		return calculateSignature(bytes);
	}

	private String calculateSignature(byte[] bytes)  throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(bytes);
		return base64Encode(signature.sign());
	}

	private String base64Encode(byte[] bytes) {
		return Base64.getUrlEncoder().encodeToString(bytes);
	}
}
