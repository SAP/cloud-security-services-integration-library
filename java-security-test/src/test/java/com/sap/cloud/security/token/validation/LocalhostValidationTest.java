/**
 * SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.TokenHeader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LocalhostValidationTest {

	@ParameterizedTest
	@ValueSource(strings = { "http://localhost:1234", "https://localhost", "https://LOCALHOST:1234", "http://127.0.0.1:1234" })
	void acceptsOnlyActualLocalhostUrls(String url) {
		assertThat(LocalhostUrlValidator.isLocalhostUrl(url)).isTrue();
		assertThat(new LocalhostIssuerValidator().isValidIssuer(url)).isTrue();
		String token = JwtGenerator.getInstance(Service.XSUAA, "client")
				.withHeaderParameter(TokenHeader.JWKS_URL, url).createToken().getTokenValue();
		assertThat(new XsuaaLocalhostJkuFactory().create(token)).isEqualTo(url);
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = {
			"https://localhost.attacker.example.invalid/jwks",
			"https://localhostevil.example.invalid",
			"https://127.0.0.1.attacker.example.invalid",
			"https://attacker.example.invalid/jwks?marker=localhost",
			"https://attacker.example.invalid/127.0.0.1/jwks",
			"https://localhost@attacker.example.invalid/jwks",
			"https://attacker@localhost/jwks",
			"http://localhost#fragment",
			"ftp://localhost/jwks",
			"http:localhost",
			"//localhost/jwks",
			"http://localhost:bad",
			"not a URL"
	})
	void rejectsSubstringAndMalformedUrls(String url) {
		assertThat(LocalhostUrlValidator.isLocalhostUrl(url)).isFalse();
		assertThat(new LocalhostIssuerValidator().isValidIssuer(url)).isFalse();
		String token = JwtGenerator.getInstance(Service.XSUAA, "client")
				.withHeaderParameter(TokenHeader.JWKS_URL, url).createToken().getTokenValue();
		assertThatThrownBy(() -> new XsuaaLocalhostJkuFactory().create(token))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void issuerRejectsQueryWhileJkuAllowsLocalhostQuery() {
		String url = "http://localhost:1234/token_keys?zid=test";
		assertThat(new LocalhostIssuerValidator().isValidIssuer(url)).isFalse();
		String token = JwtGenerator.getInstance(Service.XSUAA, "client")
				.withHeaderParameter(TokenHeader.JWKS_URL, url).createToken().getTokenValue();
		assertThat(new XsuaaLocalhostJkuFactory().create(token)).isEqualTo(url);
	}
}
