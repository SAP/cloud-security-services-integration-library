/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIdentityTest {
	private static ClientIdentity cut;
	private static ClientIdentity cut2;

	@BeforeAll
	static void init() {
		cut = new ClientCredentials("clientId", "clientSecret");
		cut2 = new ClientCertificate("CERT", "KEY", "clientId");
	}

	@Test
	void getId() {
		Assertions.assertEquals("clientId", cut.getId());
		Assertions.assertEquals("clientId", cut2.getId());
	}

	@Test
	void isCertificateBased() {
		Assertions.assertTrue(cut2.isCertificateBased());
		Assertions.assertFalse(cut.isCertificateBased());
	}

	@Test
	void getSecret() {
		Assertions.assertEquals("clientSecret", cut.getSecret());
		Assertions.assertNull(cut2.getSecret());
	}

	@Test
	void getCertificate() {
		Assertions.assertNull(cut.getCertificate());
		Assertions.assertEquals("CERT", cut2.getCertificate());
	}

	@Test
	void getKey() {
		Assertions.assertNull(cut.getKey());
		Assertions.assertEquals("KEY", cut2.getKey());
	}

	@ParameterizedTest
	@MethodSource("isValidClientCertificateTestArguments")
	void isValidClientCertificate(String cert, String key, String clientId, boolean expected) {
		ClientIdentity invalidCertificate = new ClientCertificate(cert, key, clientId);
		assertThat(invalidCertificate.isValid()).isEqualTo(expected);
	}

	@ParameterizedTest
	@MethodSource("isValidClientCredentialsTestArguments")
	void isValidClientCredentials(String clientId, String clientSecret, boolean expected) {
		ClientIdentity clientIdentity = new ClientCredentials(clientId, clientSecret);
		assertThat(clientIdentity.isValid()).isEqualTo(expected);
	}

	private static Stream<Arguments> isValidClientCredentialsTestArguments() {
		return Stream.of(
				Arguments.of("clientId", "clientSecret", true),
				Arguments.of(null, "clientSecret", false),
				Arguments.of("clientId", null, false),
				Arguments.of("clientId", "", false),
				Arguments.of("", "clientSecret", false)

		);
	}

	private static Stream<Arguments> isValidClientCertificateTestArguments() {
		return Stream.of(
				Arguments.of("CERT", "KEY", "clientId", true),
				Arguments.of("CERT", "KEY", "", false),
				Arguments.of("CERT", "", "clientId", false),
				Arguments.of("", "KEY", "clientId", false),
				Arguments.of(null, "KEY", "clientId", false),
				Arguments.of("CERT", null, "clientId", false),
				Arguments.of("CERT", "KEY", null, false));
	}
}