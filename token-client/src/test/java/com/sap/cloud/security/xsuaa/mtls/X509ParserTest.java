package com.sap.cloud.security.xsuaa.mtls;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static com.sap.cloud.security.xsuaa.mtls.X509Parser.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class X509ParserTest {

	private static String x509;
	private static final String cnf = "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM";

	@BeforeAll
	static void beforeAll() throws IOException {
		x509 = IOUtils.resourceToString("/x509Base64.txt", StandardCharsets.US_ASCII);
	}

	@Test
	void normalizeThumbprintTest() throws NoSuchAlgorithmException, CertificateException {
		String normalizedX509 = normalizeThumbprint(getX509Thumbprint(x509));
		assertFalse(normalizedX509.endsWith("="));
		assertFalse(normalizedX509.contains("\n"));
	}

	@Test
	void getX509ThumbprintTest() throws NoSuchAlgorithmException, CertificateException {
		assertEquals(cnf, (getX509Thumbprint(x509)));
	}

	@Test
	void getJwtThumbprintTest() throws NoSuchAlgorithmException {
		assertEquals(cnf, X509Parser.getJwtThumbprint(x509));
	}

}