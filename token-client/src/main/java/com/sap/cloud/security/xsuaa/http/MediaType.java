/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.http;

public enum MediaType {
	APPLICATION_JSON("application/json"), APPLICATION_FORM_URLENCODED("application/x-www-form-urlencoded");

	private final String value;

	MediaType(String value) {
		this.value = value;
	}

	public String value() {
		return value;
	}
}
