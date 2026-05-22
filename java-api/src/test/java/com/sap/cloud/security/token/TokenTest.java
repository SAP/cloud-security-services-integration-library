/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenTest {

	@Test
	public void create() {
		Token cut = Token.create("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
		assertThat(cut).isNotNull();

		cut = Token.create("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
		assertThat(cut).isNotNull();

		// Assert that custom Token factory has a priority over default
		// com.sap.cloud.security.servlet.HybridTokenFactory
		assertThat(cut.getClass().getName()).doesNotContain("AccessToken");
	}

}
