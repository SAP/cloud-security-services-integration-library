package com.sap.cloud.security.javasec.test;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.assertj.core.api.Assertions.assertThat;

public class RSAKeysTest {

	@Test
	public void generate() {
		RSAKeys keys = RSAKeys.generate();

		assertThat(keys.getPrivate()).isNotNull();
		assertThat(keys.getPublic()).isNotNull();
	}

	@Test
	public void fromKeyFiles() throws IOException, URISyntaxException, InvalidKeySpecException,
			NoSuchAlgorithmException {
		String privateKeyPath = IOUtils.resourceToURL("/privateKey.txt").getPath();
		String publicKeyPath = IOUtils.resourceToURL("/publicKey.txt").getPath();
		RSAKeys keys = RSAKeys.fromKeyFiles(publicKeyPath, privateKeyPath);

		assertThat(keys.getPrivate()).isNotNull();
		assertThat(keys.getPublic()).isNotNull();
	}
}