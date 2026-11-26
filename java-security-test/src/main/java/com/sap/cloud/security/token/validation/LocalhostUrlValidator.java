/**
 * SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation;

import java.net.URI;

/** Strict URL validation shared by the legacy localhost test helpers. */
final class LocalhostUrlValidator {

	private LocalhostUrlValidator() {
	}

	static boolean isLocalhostUrl(String value) {
		if (value == null) {
			return false;
		}
		try {
			URI uri = URI.create(value);
			return ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
					&& uri.getRawUserInfo() == null && uri.getRawFragment() == null
					&& ("localhost".equalsIgnoreCase(uri.getHost()) || "127.0.0.1".equals(uri.getHost()));
		} catch (IllegalArgumentException e) {
			return false;
		}
	}
}
