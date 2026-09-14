/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.util;

import java.net.URI;
import java.util.Map;

/**
 * Utility class for sanitizing values before logging to prevent log injection attacks.
 * Removes control characters (newlines, carriage returns, etc.) that could be used to
 * inject malicious content into log files.
 */
public final class LogSanitizer {

	private LogSanitizer() {
		// Utility class, no instantiation
	}

	/**
	 * Sanitizes a string for safe logging by removing control characters.
	 *
	 * @param value the string to sanitize
	 * @return sanitized string safe for logging, or "null" if input is null
	 */
	public static String sanitize(String value) {
		if (value == null) {
			return "null";
		}
		StringBuilder sanitized = new StringBuilder(value.length());
		for (int i = 0; i < value.length(); i++) {
			char ch = value.charAt(i);
			if (ch == '\r' || ch == '\n' || ch < 0x20 || ch == 0x7F) {
				continue;
			}
			sanitized.append(ch);
		}
		return sanitized.toString();
	}

	/**
	 * Sanitizes a URI for safe logging.
	 *
	 * @param uri the URI to sanitize
	 * @return sanitized URI string safe for logging
	 */
	public static String sanitize(URI uri) {
		return sanitize(uri != null ? uri.toString() : null);
	}

	/**
	 * Sanitizes a map for safe logging by sanitizing its string representation.
	 *
	 * @param map the map to sanitize
	 * @return sanitized map string safe for logging
	 */
	public static String sanitize(Map<?, ?> map) {
		if (map == null || map.isEmpty()) {
			return "{}";
		}
		return sanitize(map.toString());
	}

	/**
	 * Sanitizes an arbitrary object for safe logging by sanitizing its string representation.
	 * Unlike {@link #sanitize(String)}, {@link #sanitize(URI)}, and {@link #sanitize(Map)}, this
	 * method requires an explicit call-site intent — it will not be chosen by the compiler
	 * through implicit widening.
	 *
	 * @param obj the object to sanitize
	 * @return sanitized string safe for logging
	 */
	public static String sanitizeObject(Object obj) {
		return sanitize(obj != null ? obj.toString() : null);
	}
}