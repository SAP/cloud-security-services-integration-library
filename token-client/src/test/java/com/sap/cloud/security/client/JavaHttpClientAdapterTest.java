/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JavaHttpClientAdapterTest {

	private final JavaHttpClientAdapter cut = new JavaHttpClientAdapter(HttpClient.newHttpClient(), 30);

	@Test
	void execute_rejectsHeaderValueWithLineFeed() {
		SecurityHttpRequest request = SecurityHttpRequest.newBuilder()
				.uri(URI.create("https://example.com/jwks"))
				.header("x-client_cert", "abc\ndef")
				.build();

		assertThatThrownBy(() -> cut.execute(request))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("x-client_cert")
				.hasMessageContaining("CR/LF");
	}

	@Test
	void execute_rejectsHeaderValueWithCarriageReturn() {
		SecurityHttpRequest request = SecurityHttpRequest.newBuilder()
				.uri(URI.create("https://example.com/jwks"))
				.header("x-client_cert", "abc\rdef")
				.build();

		assertThatThrownBy(() -> cut.execute(request))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("x-client_cert");
	}
}