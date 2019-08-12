package com.sap.cloud.security.xsuaa.tokenflows;

import static org.junit.Assert.*;

import org.junit.Test;

public class TokenFlowExceptionTest {

	static final String MESSAGE = "Message";
	static final Exception CAUSE = new Exception();

	@Test
	public void test_constructors() {

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

		ex = new TokenFlowException(MESSAGE, CAUSE, false, false);
		assertNotNull("Exception should have a message.", ex.getMessage());
		assertNotNull("Exception should have a cause.", ex.getCause());
	}

}
