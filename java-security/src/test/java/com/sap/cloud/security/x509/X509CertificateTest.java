/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.x509;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class X509CertificateTest {

	private static String x509_base64;
	private static final String x5t = "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM";
	private static X509Certificate cut;

	@BeforeAll
	static void beforeAll() throws IOException, CertificateException {
		x509_base64 = IOUtils.resourceToString("/cf-forwarded-client-cert-base64.txt", StandardCharsets.UTF_8);
		cut = X509Certificate.newCertificate(x509_base64);
	}

	@Test
	void newCertificate_invalid() {
		assertThatThrownBy(() -> X509Certificate.newCertificate("invalid")).isInstanceOf(CertificateException.class);
	}

	@Test
	void getCertificate() {
		assertThat(cut.getCertificateValue()).isEqualTo(x509_base64);
	}

	@Test
	void getThumbprint() throws NoSuchAlgorithmException, CertificateEncodingException {
		assertThat(cut.getThumbprint()).isEqualTo(x5t);
	}

}