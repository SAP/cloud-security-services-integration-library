/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenFlowExceptionTest {

	static final String MESSAGE = "Message";
	static final Exception CAUSE = new Exception();

	@Test
	public void constructors() {

		TokenFlowException ex = new TokenFlowException();
		assertThat(ex.getMessage()).isNull();
		assertThat(ex.getCause()).isNull();

		ex = new TokenFlowException(MESSAGE);
		assertThat(ex.getMessage()).isNotNull();
		assertThat(ex.getCause()).isNull();

		ex = new TokenFlowException(CAUSE);
		assertThat(ex.getMessage()).isNotNull();
		assertThat(ex.getCause()).isNotNull();

		ex = new TokenFlowException(MESSAGE, CAUSE);
		assertThat(ex.getMessage()).isNotNull();
		assertThat(ex.getCause()).isNotNull();
	}

}
