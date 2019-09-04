package com.sap.cloud.security.xsuaa;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ObjectsUtilTest {

	@Test
	public void assertNotNull_throwsIllegalArgumentExceptionContainingMessage() {
		String message = "A message";
		assertThatThrownBy(() -> {
			ObjectsUtil.assertNotNull(null, message);
		}).isInstanceOf(IllegalArgumentException.class).hasMessage(message);
	}

	@Test
	public void assertNotNull_doesNotThrow() {
		ObjectsUtil.assertNotNull(new Object(), "Should not be thrown");
	}
}
