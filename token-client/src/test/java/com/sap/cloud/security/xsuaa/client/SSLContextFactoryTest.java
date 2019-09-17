package com.sap.cloud.security.xsuaa.client;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

public class SSLContextFactoryTest {
	SSLContextFactory cut;
	String rsaPrivateKey;
	String certificates;

	@Before
	public void setup() throws IOException {
		cut = SSLContextFactory.getInstance();
		assertThat(cut, is(SSLContextFactory.getInstance())); // singleton

		rsaPrivateKey = readFromFile("/privateRSAKey.txt");
		certificates = readFromFile("/certificates.txt");
	}

	@Test
	public void create_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			cut.create(null, rsaPrivateKey);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("x509Certificates");

		assertThatThrownBy(() -> {
			cut.create(certificates, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("rsaPrivateKey");
	}

	@Test
	/**
	 * TODO: Certificates and key are going to expire at Sept. 2020.
	 */
	public void create() throws GeneralSecurityException, IOException {
		assertThat(cut.create(certificates, rsaPrivateKey), is(notNullValue()));
	}

	public String readFromFile(String file) throws IOException {
		return IOUtils.resourceToString(file, StandardCharsets.UTF_8);
	}

}
