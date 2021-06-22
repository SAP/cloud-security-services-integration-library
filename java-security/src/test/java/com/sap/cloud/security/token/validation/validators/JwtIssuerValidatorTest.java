/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import static com.sap.cloud.security.token.TokenClaims.IAS_ISSUER;
import static com.sap.cloud.security.token.TokenClaims.ISSUER;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

public class JwtIssuerValidatorTest {

	private JwtIssuerValidator cut;
	private Token token;
	private final String[] domains = new String[] { "customer.ondemand.com", "accounts400.ondemand.com" };

	@Before
	public void setup() {
		cut = new JwtIssuerValidator(Arrays.asList(domains));
		token = Mockito.mock(Token.class);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new JwtIssuerValidator(null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("JwtIssuerValidator", "domain(s)");

		assertThatThrownBy(() -> {
			new JwtIssuerValidator(new ArrayList<>());
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("JwtIssuerValidator", "domain(s)");
	}

	@Test
	public void validationFails_whenIssuerDomainDoesNotMatchIdentityProviderDomains() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://otherdomain.test.ondemand.com");
		assertThat(cut.validate(token).isValid(), is(false));
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = {"  "})
	public void validationFails_whenIssuerIsEmptyOrNull(String issuer) {
		cut = new JwtIssuerValidator(Collections.singletonList("accounts400.ondemand.com"));
		token = Mockito.mock(Token.class);

		when(token.getClaimAsString(ISSUER)).thenReturn(issuer);
		when(token.getClaimAsString(IAS_ISSUER)).thenReturn("https://test.accounts400.ondemand.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Issuer validation can not be performed because Jwt token does not contain 'iss' claim."));
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = {"  "})
	public void validationSucceeds_whenIasIssuerIsEmptyOrNull(String iasIssuer) {
		cut = new JwtIssuerValidator(Collections.singletonList("accounts400.ondemand.com"));
		token = Mockito.mock(Token.class);

		when(token.getClaimAsString(ISSUER)).thenReturn("https://test.accounts400.ondemand.com");
		when(token.getClaimAsString(IAS_ISSUER)).thenReturn(iasIssuer);
		ValidationResult validationResult = cut.validate(token);
		assertTrue(validationResult.isValid());
	}

	@Test
	public void validationFails_withoutMatchingIasIssuer() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://otherDomain.accounts.ondemand.com");
		when(token.getClaimAsString(IAS_ISSUER)).thenReturn("https://iasDomain.accounts.ondemand.com");

		ValidationResult validationResult = cut.validate(token);
		assertTrue(validationResult.isErroneous());
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer is not trusted because 'ias_iss' 'https://iasDomain.accounts.ondemand.com' doesn't match any of these domains '[customer.ondemand.com, accounts400.ondemand.com]' of the identity provider."));
	}

	@ParameterizedTest
	@CsvSource(
			{"https://subdomain.accounts400.ondemand.com#anyFragment_keys",
			 "https://subdomain.accounts400.ondemand.com?a=b",
			 "\0://myauth.com",
			 "https://otherDomain.org?accounts400.ondemand.com",
			 "subdomain.accounts400.ondemand.com"})
	public void validationFails_issuerUrl(String issuer) {
		cut = new JwtIssuerValidator(Arrays.asList(domains));
		token = Mockito.mock(Token.class);

		when(token.getClaimAsString(ISSUER)).thenReturn(issuer);
		when(token.getClaimAsString(IAS_ISSUER)).thenReturn("https://otherDomain.accounts400.ondemand.com");

		ValidationResult validationResult = cut.validate(token);
		assertTrue(validationResult.isErroneous());
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because 'iss' claim"));
	}

	@ParameterizedTest
	@CsvSource(
			{"https://subdomain.accounts400.ondemand.com#anyFragment_keys",
			 "https://subdomain.accounts400.ondemand.com?a=b",
			 "\0://myauth.com",
			 "https://otherDomain.org?accounts400.ondemand.com",
			 "subdomain.accounts400.ondemand.com"})
	public void validationFails_iasIssuerUrl(String issuer) {
		cut = new JwtIssuerValidator(Arrays.asList(domains));
		token = Mockito.mock(Token.class);

		when(token.getClaimAsString(ISSUER)).thenReturn("https://otherDomain.accounts400.ondemand.com");
		when(token.getClaimAsString(IAS_ISSUER)).thenReturn(issuer);

		ValidationResult validationResult = cut.validate(token);
		assertTrue(validationResult.isErroneous());
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because 'ias_iss' claim"));
	}

	@ParameterizedTest
	@CsvSource(
			{"https://otherDomain.accounts400.ondemand.com,",
			"https://paas.accounts400.ondemand.com,",
			"https://nestle.com,https://paas.accounts400.ondemand.com,"})
	public void validationSucceeds(String issuer, String iasIssuer) {
		cut = new JwtIssuerValidator(Arrays.asList(domains));
		token = Mockito.mock(Token.class);

		when(token.getClaimAsString(ISSUER)).thenReturn(issuer);
		when(token.getClaimAsString(IAS_ISSUER)).thenReturn(iasIssuer);

		ValidationResult validationResult = cut.validate(token);
		assertTrue(validationResult.isValid());
	}
}
