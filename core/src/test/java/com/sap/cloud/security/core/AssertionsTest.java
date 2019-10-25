package com.sap.cloud.security.core;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.Test;

import com.sap.cloud.security.core.Assertions;

public class AssertionsTest {

	@Test
	public void assertNotNull_throwsIllegalArgumentExceptionContainingMessage() {
		String message = "A message";
		assertThatThrownBy(() -> {
			Assertions.assertNotNull(null, message);
		}).isInstanceOf(IllegalArgumentException.class).hasMessage(message);
	}

	@Test
	public void assertNotNull_doesNotThrow() {
		Assertions.assertNotNull(new Object(), "Should not be thrown");
	}
}
