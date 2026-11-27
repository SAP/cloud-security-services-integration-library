/**
 * SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import java.net.URI;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class UriUtilLabelTest {

	private final URI tokenEndpointUri = URI.create("https://tenant-a.example.com/oauth/token");

	@ParameterizedTest
	@MethodSource("validLabels")
	void replacesValidLabels(String subdomain) {
		assertThat(UriUtil.replaceSubdomain(tokenEndpointUri, subdomain))
				.isEqualTo(URI.create("https://" + subdomain + ".example.com/oauth/token"));
	}

	static Stream<String> validLabels() {
		return Stream.of("a", "Z", "0", "ab", "tenant-b", "Tenant-123", "a--b", "a".repeat(63));
	}

	@ParameterizedTest
	@MethodSource("invalidLabels")
	void rejectsInvalidLabels(String subdomain) {
		assertThatIllegalArgumentException().isThrownBy(() -> UriUtil.replaceSubdomain(tokenEndpointUri, subdomain))
				.withMessage("Subdomain must be a single RFC 1123 DNS label");
	}

	static Stream<String> invalidLabels() {
		return Stream.of("tenant.example", "tenant/", "tenant//", "tenant?", "tenant#", "tenant@other",
				"tenant:8080", "tenant\\", "tenant%2F", "tenant_name", "-tenant", "tenant-", "-",
				" tenant", "tenant ", "ten ant", "tenant\n", "tenant\r", "tenant\t", "tenant\u0000",
				"täst", "租户", "\u00a0", "\u2003", "a".repeat(64));
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { " ", "\t\r\n" })
	void preservesBlankValueFallback(String subdomain) {
		assertThat(UriUtil.replaceSubdomain(tokenEndpointUri, subdomain)).isSameAs(tokenEndpointUri);
	}

	@ParameterizedTest
	@ValueSource(strings = { "http://localhost", "localhost", "/oauth/token", "mailto:tenant@example.com",
			"file:/oauth/token", "https:/oauth/token" })
	void preservesUnsupportedUriFallback(String value) {
		URI uri = URI.create(value);
		assertThat(UriUtil.replaceSubdomain(uri, "tenant-b")).isSameAs(uri);
		assertThatIllegalArgumentException().isThrownBy(() -> UriUtil.replaceSubdomain(uri, "tenant.example"));
	}

	@Test
	void preservesOtherUriComponents() {
		URI uri = URI.create("https://user:password@tenant-a.example.com:8443/oauth/token?key=value#section");
		URI replaced = UriUtil.replaceSubdomain(uri, "Tenant-B");
		assertThat(replaced.getHost()).isEqualTo("Tenant-B.example.com");
		assertThat(replaced.getScheme()).isEqualTo(uri.getScheme());
		assertThat(replaced.getUserInfo()).isEqualTo(uri.getUserInfo());
		assertThat(replaced.getPort()).isEqualTo(uri.getPort());
		assertThat(replaced.getPath()).isEqualTo(uri.getPath());
		assertThat(replaced.getQuery()).isEqualTo(uri.getQuery());
		assertThat(replaced.getFragment()).isEqualTo(uri.getFragment());
	}

	@Test
	void rejectsNullUri() {
		assertThatIllegalArgumentException().isThrownBy(() -> UriUtil.replaceSubdomain(null, "tenant-b"));
	}
}
