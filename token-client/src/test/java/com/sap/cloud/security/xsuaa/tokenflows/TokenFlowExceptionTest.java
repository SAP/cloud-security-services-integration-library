/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class TokenFlowExceptionTest {

	static final String MESSAGE = "Message";
	static final Exception CAUSE = new Exception();

	@Test
	public void constructors() {

		TokenFlowException ex = new TokenFlowException();
		assertNull("Exception should not have any message.", ex.getMessage());
		assertNull("Exception should not have any cause.", ex.getCause());

		ex = new TokenFlowException(MESSAGE);
		assertNotNull("Exception should have a message.", ex.getMessage());
		assertNull("Exception should not have any cause.", ex.getCause());

		ex = new TokenFlowException(CAUSE);
		assertNotNull("Exception should not have a default message.", ex.getMessage());
		assertNotNull("Exception should have a cause.", ex.getCause());

		ex = new TokenFlowException(MESSAGE, CAUSE);
		assertNotNull("Exception should have a message.", ex.getMessage());
		assertNotNull("Exception should have a cause.", ex.getCause());
	}

}
