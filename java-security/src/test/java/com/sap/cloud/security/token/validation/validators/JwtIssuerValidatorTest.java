/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
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
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

class JwtIssuerValidatorTest {

	private JwtIssuerValidator cut;
	private Token token;
	private final String[] domains = new String[] { "customer.ondemand.com", "accounts400.ondemand.com" };

	@BeforeEach
	void setup() {
		cut = new JwtIssuerValidator(Arrays.asList(domains));
		token = Mockito.mock(SapIdToken.class);
	}

	@Test
	void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> new JwtIssuerValidator(null)).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContainingAll("JwtIssuerValidator", "domain(s)");

		assertThatThrownBy(() -> new JwtIssuerValidator(new ArrayList<>())).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContainingAll("JwtIssuerValidator", "domain(s)");
	}

	@Test
	void validationFails_whenIssuerDomainDoesNotMatchIdentityProviderDomains() {
		configureMock("https://otherdomain.test.ondemand.com", null);
		assertThat(cut.validate(token).isValid(), is(false));
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "  " })
	void validationIgnoresEmptyIssuer_whenIasIssuerIsGiven(String issuer) {
		cut = new JwtIssuerValidator(Collections.singletonList("accounts400.ondemand.com"));
		configureMock(issuer, "https://test.accounts400.ondemand.com");

		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(true));
	}

	@Test
	void validationSucceeds_whenIasIssuerIsEmptyOrNull() {
		cut = new JwtIssuerValidator(Collections.singletonList("accounts400.ondemand.com"));
		configureMock("https://test.accounts400.ondemand.com", null);

		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(false));
	}

	@Test
	void validationFails_withoutMatchingIasIssuer() {
		configureMock("https://otherDomain.accounts400.ondemand.com", "https://iasDomain.accounts.ondemand.com");

		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer is not trusted because issuer 'https://iasDomain.accounts.ondemand.com' doesn't match any of these domains '[customer.ondemand.com, accounts400.ondemand.com]' of the identity provider."));
	}

	@Test
	void validationIgnoresInvalidIssuer_whenIasIssuerIsGiven() {
		cut = new JwtIssuerValidator(Arrays.asList(domains));
		configureMock("invalid_url", "https://otherDomain.accounts400.ondemand.com");

		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(false));
	}

	@ParameterizedTest
	@CsvSource({ "https://subdomain.accounts400.ondemand.com#anyFragment_keys",
			"https://subdomain.accounts400.ondemand.com?a=b",
			"\0://myauth.com",
			"https://otherDomain.org?accounts400.ondemand.com", })
	void validationFails_iasIssuerUrl(String iasIssuer) {
		cut = new JwtIssuerValidator(Arrays.asList(domains));
		configureMock("https://otherDomain.accounts400.ondemand.com", iasIssuer);

		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because issuer "));
	}

	@ParameterizedTest
	@CsvSource({ "https://otherDomain.accounts400.ondemand.com,",
			"https://paas.accounts400.ondemand.com,",
			"https://nestle.com,paas.accounts400.ondemand.com,",
			"subdomain.accounts400.ondemand.com,",
			"https://nestle.com,https://paas.accounts400.ondemand.com," })
	void validationSucceeds(String issuer, String iasIssuer) {
		cut = new JwtIssuerValidator(Arrays.asList(domains));
		configureMock(issuer, iasIssuer);

		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(true));
	}

	private void configureMock(String issuer, String iasIssuer) {
		when(token.getService()).thenReturn(Service.IAS);
		when(token.getIssuer()).thenCallRealMethod();
		when(token.getClaimAsString(TokenClaims.ISSUER)).thenReturn(issuer);
		when(token.getClaimAsString(TokenClaims.IAS_ISSUER)).thenReturn(iasIssuer);
		when(token.hasClaim("ias_iss")).thenReturn(iasIssuer != null);
	}
}
