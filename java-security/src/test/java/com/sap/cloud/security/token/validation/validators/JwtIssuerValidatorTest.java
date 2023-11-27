/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

class JwtIssuerValidatorTest {

	private JwtIssuerValidator cut;
	private Token token;
	private final String[] trustedDomains = new String[] { "customer.ondemand.com", "accounts400.ondemand.com" };

	@BeforeEach
	void setup() {
		cut = new JwtIssuerValidator(Arrays.asList(trustedDomains));
		token = Mockito.mock(SapIdToken.class);
		when(token.getService()).thenReturn(Service.IAS);
	}

	@Test
	void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> new JwtIssuerValidator(null)).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContainingAll("JwtIssuerValidator", "domain(s)");

		assertThatThrownBy(() -> new JwtIssuerValidator(new ArrayList<>())).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContainingAll("JwtIssuerValidator", "domain(s)");
	}

	@ParameterizedTest
	@CsvSource({
			"accounts400.ondemand.com",
			"https://accounts400.ondemand.com",
			"tenant.accounts400.ondemand.com",
			"https://tenant.accounts400.ondemand.com",
			"tenant-0815WithNumbers.accounts400.ondemand.com",
			"https://tenant-0815WithNumbers.accounts400.ondemand.com"
	})
	void validationSucceeds_forValidIssuers(String issuer) {
		when(token.getIssuer()).thenReturn(issuer);

		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(true));
		assertThat(validationResult.isErroneous(), is(false));
	}

	/**
	 * Test ensures that issuer validation also succeeds for servers running on http://localhost:<PORT>, e.g. when using java-security-test module.
	 */
	@Test
	void supportsHttpLocalhostIssuers() {
		String localDomain = "localhost:5555";
		JwtIssuerValidator cut = new JwtIssuerValidator(List.of(localDomain));
		when(token.getIssuer()).thenReturn("http://" + localDomain);

		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(true));
		assertThat(validationResult.isErroneous(), is(false));
	}

	@Test
	void validationFails_whenSubdomainHasMoreThan63Characters() {
		for(String d : trustedDomains) {
			when(token.getIssuer()).thenReturn("https://a." + d);
			assertThat(cut.validate(token).isValid(), is(true));

			when(token.getIssuer()).thenReturn("https://" + "a".repeat(63) + "." + d);
			assertThat(cut.validate(token).isValid(), is(true));

			when(token.getIssuer()).thenReturn("https://" + "a".repeat(64) + "." + d);
			assertThat(cut.validate(token).isValid(), is(false));
		}
	}

	@ParameterizedTest
	@CsvSource({
			"https://accou\tnts400.ondemand.com",
			"https://accou\nnts400.ondemand.com",
			"https://accounts400.onde\tmand.com",
			"https://accounts400.onde\nmand.com",
			"https://tena\tnt.accounts400.ondemand.com",
			"https://tena\nnt.accounts400.ondemand.com",
			"https://tenant.accounts400.onde\tmand.com",
			"https://tenant.accounts400.onde\nmand.com"
	})
	void validationFails_whenIssuerContainsInvisibleCharacters(String issuer) {
		when(token.getIssuer()).thenReturn(issuer);
		assertThat(cut.validate(token).isValid(), is(false));
		assertThat(cut.validate(token).isErroneous(), is(true));
	}

	@ParameterizedTest
	@CsvSource({
			"https://accounts400%2eondemand.com",
			"https://accounts400.ondemand.com%2eattackerdomain.com",
			"https://tenant%2eaccounts400.ondemand.com",
			"https://attackerdomain.com%2eaccounts400.ondemand.com",
			"tenant%2d0815WithNumbers.accounts400.ondemand.com",
	})
	void validationFails_whenIssuerContainsEncodedCharacters(String issuer) {
		when(token.getIssuer()).thenReturn(issuer);
		assertThat(cut.validate(token).isValid(), is(false));
		assertThat(cut.validate(token).isErroneous(), is(true));
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "  " })
	void validationFails_whenIssuerIsEmpty(String issuer) {
		when(token.getIssuer()).thenReturn(issuer);
		assertThat(cut.validate(token).isValid(), is(false));
		assertThat(cut.validate(token).isErroneous(), is(true));
	}

	@Test
	void validationFails_whenIssuerIsNotAValidURL() {
		when(token.getIssuer()).thenReturn("https://");
		assertThat(cut.validate(token).isValid(), is(false));
		assertThat(cut.validate(token).isErroneous(), is(true));

		when(token.getIssuer()).thenReturn("http://");
		assertThat(cut.validate(token).isValid(), is(false));
		assertThat(cut.validate(token).isErroneous(), is(true));

		when(token.getIssuer()).thenReturn("http://" + trustedDomains[0]);
		assertThat(cut.validate(token).isValid(), is(false));
		assertThat(cut.validate(token).isErroneous(), is(true));
	}

	@ParameterizedTest
	@CsvSource({
			"https://accounts400.ondemand.coma",
			"https://accounts400.ondemand.com0",
			"https://accounts400.ondemand.com/",
			"https://accounts400.ondemand.com/path",
			"https://accounts400.ondemand.com%2f",
			"https://accounts400.ondemand.com%2fpath",
			"https://accounts400.ondemand.com&",
			"https://accounts400.ondemand.com%26",
			"https://accounts400.ondemand.com?",
			"https://accounts400.ondemand.com?foo",
			"https://accounts400.ondemand.com?foo=bar",
			"https://accounts400.ondemand.com%3f",
			"https://accounts400.ondemand.com%3ffoo",
			"https://accounts400.ondemand.com%3ffoo=bar",
			"https://accounts400.ondemand.com#",
			"https://accounts400.ondemand.com#foo",
			"https://accounts400.ondemand.com%23",
			"https://accounts400.ondemand.com%23foo",
			"https://user@accounts400.ondemand.com",
			"https://user%40accounts400.ondemand.com",
	})
	void validationFails_whenIssuerContainsMoreThanDomain(String issuer) {
		when(token.getIssuer()).thenReturn(issuer);
		assertThat(cut.validate(token).isValid(), is(false));
		assertThat(cut.validate(token).isErroneous(), is(true));
	}

	@ParameterizedTest
	@CsvSource({
			"https://attackerdomain.com",
			"https://tenant.attackerdomain.com",
			"https://myaccounts400.ondemand.com",
			"https://accounts400.ondemand.com.attackerDomain.com",
			"https://accounts400.ondemand.com%2eattackerDomain.com",
			"https://accounts400.ondemand.com%2dattackerDomain.com",
	})
	void validationFails_whenIssuerIsNotASubdomainOfTrustedDomains(String issuer) {
		when(token.getIssuer()).thenReturn(issuer);
		assertThat(cut.validate(token).isValid(), is(false));
		assertThat(cut.validate(token).isErroneous(), is(true));
	}
}
