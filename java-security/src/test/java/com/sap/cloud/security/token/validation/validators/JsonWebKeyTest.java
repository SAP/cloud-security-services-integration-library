/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import org.junit.jupiter.api.Test;

import org.junit.jupiter.api.BeforeEach;

import static org.assertj.core.api.Assertions.assertThat;

public class JsonWebKeyTest {
	private JsonWebKey cut;

	@BeforeEach
	public void setup() {
		cut = JsonWebKeyTestFactory.create();
	}

	@Test
	public void equalsByInstance() {
		assertThat(cut.equals(cut)).isTrue();
	}

	@Test
	public void equalsByFields() {
		assertThat(cut.equals(JsonWebKeyTestFactory.create())).isTrue();
		assertThat(cut.hashCode()).isEqualTo(JsonWebKeyTestFactory.create().hashCode());
	}

	@Test
	public void notEqualsByFields() {
		assertThat(cut.equals(JsonWebKeyTestFactory.createDefault())).isFalse();
		assertThat(cut.hashCode()).isNotEqualTo(JsonWebKeyTestFactory.createDefault().hashCode());
	}

}
