package com.sap.cloud.security.javasec.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

public class RSAKeys {

	private static final String RSA = "RSA";
	private static final String KEY_BEGIN_END_REGEX = "-+(BEGIN|END)\\s+(\\w+\\s?)+-+";

	private final KeyPair keyPair;

	public static RSAKeys generate() {
		KeyPair theKeyPair = generateKeyPair();
		return new RSAKeys(new KeyPair(theKeyPair.getPublic(), theKeyPair.getPrivate()));
	}

	public static RSAKeys fromKeyFiles(String publicKeyPath, String privateKeyPath)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		KeyPair keyPair = new KeyPair(loadPublicKey(publicKeyPath), loadPrivateKey(privateKeyPath));
		return new RSAKeys(keyPair);
	}

	public PublicKey getPublic() {
		return keyPair.getPublic();
	}

	public PrivateKey getPrivate() {
		return keyPair.getPrivate();
	}

	private RSAKeys(KeyPair keyPair) {
		this.keyPair = keyPair;
	}

	public static PublicKey loadPublicKey(String publicKeyPath)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String publicKeyString = readFileAndReplaceBeginEnd(Paths.get(publicKeyPath));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(base64Decode(publicKeyString));
		return KeyFactory.getInstance(RSA).generatePublic(spec);
	}

	public static PrivateKey loadPrivateKey(String privateKeyPath)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String privateKeyString = readFileAndReplaceBeginEnd(Paths.get(privateKeyPath));
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(base64Decode(privateKeyString));
		return KeyFactory.getInstance(RSA).generatePrivate(spec);
	}

	private static byte[] base64Decode(String publicKeyString) {
		return Base64.getDecoder().decode(publicKeyString);
	}

	private static String readFileAndReplaceBeginEnd(Path filePath) throws IOException {
		String stringy = new String(Files.readAllBytes(filePath));
		String content = Files.readAllLines(filePath).stream().collect(Collectors.joining(""));
		return content.replaceAll(KEY_BEGIN_END_REGEX, "");
	}

	private static KeyPair generateKeyPair() {
		try {
			return KeyPairGenerator.getInstance(RSA).generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

}
