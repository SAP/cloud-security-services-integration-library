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

import static org.assertj.core.api.Assertions.assertThat;

class X509CertificateTest {

	private static String x509_base64;
	private static final String x5t = "fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM";
	private static X509Certificate cut;

	@BeforeAll
	static void beforeAll() throws IOException {
		x509_base64 = IOUtils.resourceToString("/cf-forwarded-client-cert-base64.txt", StandardCharsets.UTF_8);
		cut = X509Certificate.newCertificate(x509_base64);
	}

	@Test
	void newCertificate_invalid() {
		assertThat(X509Certificate.newCertificate("invalid")).isNull();
	}

	@Test
	void getThumbprint() {
		assertThat(cut.getThumbprint()).isEqualTo(x5t);
	}

	@Test
	void getSubjectDN() {
		assertThat(cut.getSubjectDN()).isEqualTo(
				"CN=bdcd300c-b202-4a7a-bb95-2a7e6d15fe47/2b585405-d391-4986-b76d-b4f24685f3c8, L=aoxk2addh.accounts400.ondemand.com, OU=8e1affb2-62a1-43cc-a687-2ba75e4b3d84, OU=Canary, OU=SAP Cloud Platform Clients, O=SAP SE, C=DE");
	}
	@Test
	void getIssuerDN() {
		assertThat(cut.getIssuerDN(X500Principal.RFC2253)).isEqualTo(
				"CN=SAP Cloud Platform Client CA,OU=SAP Cloud Platform Clients,O=SAP SE,L=EU10-Canary,C=DE");
	}
	@Test
	void getSubjectDNMap() {
		assertThat(cut.getSubjectDNMap().size()).isEqualTo(5);
		assertThat(cut.getSubjectDNMap().get("CN"))
				.isEqualTo("bdcd300c-b202-4a7a-bb95-2a7e6d15fe47/2b585405-d391-4986-b76d-b4f24685f3c8");
		assertThat(cut.getSubjectDNMap().get("OU"))
				.isEqualTo("8e1affb2-62a1-43cc-a687-2ba75e4b3d84,Canary,SAP Cloud Platform Clients");
	}
}