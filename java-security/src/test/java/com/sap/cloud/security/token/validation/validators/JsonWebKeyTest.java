/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Before;
import org.junit.Test;

public class JsonWebKeyTest {
	private JsonWebKey cut;

	@Before
	public void setup() {
		cut = JsonWebKeyTestFactory.create();
	}

	@Test
	public void equalsByInstance() {
		assertThat(cut.equals(cut), equalTo(true));
	}

	@Test
	public void equalsByFields() {
		assertThat(cut.equals(JsonWebKeyTestFactory.create()), equalTo(true));
		assertThat(cut.hashCode(), equalTo(JsonWebKeyTestFactory.create().hashCode()));
	}

	@Test
	public void notEqualsByFields() {
		assertThat(cut.equals(JsonWebKeyTestFactory.createDefault()), equalTo(false));
		assertThat(cut.hashCode(), not(equalTo(JsonWebKeyTestFactory.createDefault().hashCode())));
	}

}
