/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class ClientCredentialsTest {
	ClientIdentity cut = new ClientCredentials("clientId", "clientSecret");

	@Test
	public void equals() {
		assertThat(cut.equals(cut)).isTrue();
		assertThat(cut.equals(new ClientCredentials("clientId", "clientSecret"))).isTrue();
	}

	@Test
	public void not_equals() {
		assertThat(cut.equals(new ClientCredentials("clientId2", "clientSecret"))).isFalse();
		assertThat(cut.equals(new ClientCredentials("clientId", "clientSecret2"))).isFalse();
		assertThat(cut.equals(null)).isFalse();
		assertThat(cut.equals(new Object())).isFalse();
	}

	@Test
	public void hashCoded() {
		int cutHashCode = cut.hashCode();
		assertThat(cutHashCode).isNotEqualTo(0);
		assertThat(cutHashCode).isEqualTo(new ClientCredentials("clientId", "clientSecret").hashCode());
		assertThat(cutHashCode).isNotEqualTo(new ClientCredentials("clientId2", "clientSecret").hashCode());
	}

	@Test
	public void stringify() {
		assertThat(cut.toString()).isEqualTo("clientId:clientSecret");
	}

	@Test
	public void testClientIdentityResolution() {
		assertTrue(cut.isValid());
		assertFalse(cut.isCertificateBased());
		assertNull(cut.getCertificate());
		assertNull(cut.getKey());
		assertEquals("clientId", cut.getId());
		assertEquals("clientSecret", cut.getSecret());
	}
}
