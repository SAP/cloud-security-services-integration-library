/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.json;

/**
 * An extraordinary runtime exception during json parsing.
 */
public class JsonParsingException extends RuntimeException {

	public JsonParsingException(String message) {
		super(message);
	}

	public JsonParsingException(String message, Throwable cause) {
		super(message, cause);
	}
}
