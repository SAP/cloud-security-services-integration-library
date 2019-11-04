package com.sap.cloud.security.xsuaa;

public class Assertions {

	private Assertions() {
	}

	public static void assertNotNull(Object object, String message) {
		if (object == null) {
			throw new IllegalArgumentException(message);
		}
	}

	public static void assertNotEmpty(String string, String message) {
		if (string == null || string.trim().isEmpty()) {
			throw new IllegalArgumentException(message);
		}
	}
}
