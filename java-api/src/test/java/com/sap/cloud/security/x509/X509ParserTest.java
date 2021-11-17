package com.sap.cloud.security.x509;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static com.sap.cloud.security.x509.X509Parser.getX509Thumbprint;
import static com.sap.cloud.security.x509.X509Parser.normalizeThumbprint;
import static org.assertj.core.api.Assertions.assertThat;

class X509ParserTest {

	private static String x509_base64;
	private static String x509_pem_format;
	private static final String x5t = "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM";

	@BeforeAll
	static void beforeAll() throws IOException {
		x509_base64 = IOUtils.resourceToString("/cf-forwarded-client-cert-base64.txt", StandardCharsets.UTF_8);
		x509_pem_format = IOUtils.resourceToString("/k8s-forwarded-client-cert-pem.txt", StandardCharsets.UTF_8);
	}

	@Test
	void formatBase64Cert() {
		String formattedBase64 = X509Parser.formatBase64Cert(x509_pem_format);
		assertThat(formattedBase64)
				.startsWith("-----BEGIN CERTIFICATE-----\n")
				.endsWith("\n-----END CERTIFICATE-----");
		assertThat(formattedBase64.chars().filter(ch -> ch == '\n').count()).isEqualTo(5);

		String formattedBase64_2 = X509Parser.formatBase64Cert(x509_base64);
		assertThat(formattedBase64_2)
				.startsWith("-----BEGIN CERTIFICATE-----\n")
				.endsWith("\n-----END CERTIFICATE-----");
		assertThat(formattedBase64_2.chars().filter(ch -> ch == '\n').count()).isEqualTo(2);

	}

	@Test
	void normalizeThumbprintTest() throws NoSuchAlgorithmException, CertificateException {
		String normalizedX509 = normalizeThumbprint(getX509Thumbprint(x509_base64));
		assertThat(normalizedX509)
				.doesNotEndWith("=")
				.doesNotContain("\n");
	}

	@Test
	void getX509ThumbprintTest() throws NoSuchAlgorithmException, CertificateException {
		assertThat(getX509Thumbprint(x509_base64)).isEqualTo(x5t);
	}

	@Test
	void getJwtThumbprintTest() throws NoSuchAlgorithmException {
		assertThat(X509Parser.getCertificateThumbprint(x509_base64)).isEqualTo(x5t);
	}

	@Test
	void testRegex() {
		String testCase = "I\nDon't\nWant\r\nTo Be\r On New Line";
		String result = testCase.replaceAll("\\s", "");
		assertThat(result).isEqualTo("IDon'tWantToBeOnNewLine");
	}
}