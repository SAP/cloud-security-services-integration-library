/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import java.util.List;

public class Assertions {

	private Assertions() {
	}

	public static void assertNotNull(Object object, String message) {
		if (object == null) {
			throw new IllegalArgumentException(message);
		}
	}

	public static void assertHasText(String string, String message) {
		if (string == null || string.trim().isEmpty()) {
			throw new IllegalArgumentException(message);
		}
	}

	public static void assertNotEmpty(List<?> list, String message) {
		if (list == null || list.isEmpty()) {
			throw new IllegalArgumentException(message);
		}
	}
}
