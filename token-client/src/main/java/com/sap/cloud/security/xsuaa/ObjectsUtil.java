package com.sap.cloud.security.xsuaa;

public class ObjectsUtil {
	public static void assertNotNull(Object object, String message) {
		if (object == null) {
			throw new IllegalArgumentException(message);
		}
	}
}
