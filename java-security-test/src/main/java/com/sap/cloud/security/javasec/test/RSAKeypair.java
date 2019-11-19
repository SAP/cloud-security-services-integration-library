package com.sap.cloud.security.javasec.test;

import org.junit.rules.ExternalResource;

import java.security.*;

public class RSAKeypair extends ExternalResource {

	private final KeyPair keyPair;

	public RSAKeypair()  {
		keyPair = generateKeyPair();
	}

	public PublicKey getPublic() {
		return keyPair.getPublic();
	}

	public PrivateKey getPrivate() {
		return keyPair.getPrivate();
	}

	private KeyPair generateKeyPair() {
		try {
			return KeyPairGenerator.getInstance("RSA").generateKeyPair();
		} catch ( NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

}
