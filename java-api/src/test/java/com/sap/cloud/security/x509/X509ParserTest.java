/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.x509;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static com.sap.cloud.security.x509.X509Parser.getCertificateThumbprint;
import static com.sap.cloud.security.x509.X509Parser.parseCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class X509ParserTest {

	public static final String DN_ISSUER_VALUE = "CN=SAP Cloud Platform Client CA, OU=SAP Cloud Platform Clients, O=SAP SE, L=EU10-Canary, C=DE";
	private static String x509_base64;
	private static String x509_pem_format;
	private static final String x5t = "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM";

	@BeforeAll
	static void beforeAll() throws IOException {
		x509_base64 = IOUtils.resourceToString("/cf-forwarded-client-cert-base64.txt", StandardCharsets.UTF_8);
		x509_pem_format = IOUtils.resourceToString("/k8s-forwarded-client-cert-pem.txt", StandardCharsets.UTF_8);
	}

	@Test
	void parseCertificate_validBase64() throws CertificateException {
		assertThat(parseCertificate(x509_base64).getIssuerX500Principal().getName(X500Principal.RFC1779)).isEqualTo(DN_ISSUER_VALUE);
	}

	@Test
	void parseCertificate_validPEM() throws CertificateException {
		assertThat(parseCertificate(x509_pem_format).getIssuerX500Principal().getName(X500Principal.RFC1779)).isEqualTo(DN_ISSUER_VALUE);
	}

	@Test
	void parseCertificate_invalidCertificate() {
		assertThatThrownBy(() -> parseCertificate("R93AEV2m52aX6yXCfzwkL92cW1zBsCuNi82K9PiNmzb/WVB5i7VdXUwAd7bI9ACb"))
				.isInstanceOf(CertificateException.class);
		assertThatThrownBy(() -> parseCertificate(""))
				.isInstanceOf(CertificateException.class);
		assertThatThrownBy(() -> parseCertificate(null))
				.isInstanceOf(NullPointerException.class)
				.hasMessageStartingWith("The provided Certificate can not be null");
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
	void getX509ThumbprintTest() throws NoSuchAlgorithmException, CertificateException {
		assertThat(getCertificateThumbprint(parseCertificate(x509_base64))).isEqualTo(x5t);
	}

	@Test
	void testRegex() {
		String testCase = "I\nDon't\nWant\r\nTo Be\r On New Line";
		String result = testCase.replaceAll("\\s", "");
		assertThat(result).isEqualTo("IDon'tWantToBeOnNewLine");
	}
}