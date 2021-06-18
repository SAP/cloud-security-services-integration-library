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
import org.mockito.Mockito;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.sap.cloud.security.token.TokenClaims.IAS_ISSUER;
import static com.sap.cloud.security.token.TokenClaims.ISSUER;
import static com.sap.cloud.security.token.TokenHeader.JWKS_URL;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

public class JwtIssuerValidatorTest {

	private JwtIssuerValidator cut;
	private Token token;
	private String[] domains = new String[] { "customer.ondemand.com", "accounts400.ondemand.com" };

	@Before
	public void setup() {
		cut = new JwtIssuerValidator(Arrays.asList(domains));
		token = Mockito.mock(Token.class);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new JwtIssuerValidator((List<String>) null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("JwtIssuerValidator", "domain(s)");

		assertThatThrownBy(() -> {
			new JwtIssuerValidator(new ArrayList<>());
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("JwtIssuerValidator", "domain(s)");
	}

	@Test
	public void validationSucceeds_whenIssuerDomainMatchesIdentityProviderDomains() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://paas.accounts400.ondemand.com");
		assertThat(cut.validate(token).isValid(), is(true));
	}

	@Test
	public void validationFails_whenIssuerDomainDoesNotMatchIdentityProviderDomains() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://otherdomain.test.ondemand.com");
		assertThat(cut.validate(token).isValid(), is(false));
	}

	@Test
	public void validationFails_whenIssuerWithoutHttpSchemeMatchesIdentityProviderUrl() {
		when(token.getClaimAsString(ISSUER)).thenReturn("subdomain.accounts400.ondemand.com");

		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer is not trusted because 'iss' claim 'subdomain.accounts400.ondemand.com' does not provide a valid URI (missing http scheme)."));
	}

	@Test
	public void validationFails_whenIssuerEndsWithIdentityProviderUrlQueryParameter() {
		cut = new JwtIssuerValidator(Collections.singletonList("accounts400.ondemand.com"));
		when(token.getClaimAsString(ISSUER)).thenReturn("https://otherDomain.org?accounts400.ondemand.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer is not trusted because 'iss' claim 'https://otherDomain.org?accounts400.ondemand.com' does not provide a valid URI. Please contact your Identity Provider Administrator."));
	}

	@Test
	public void validationFails_whenIasIssuerEndsWithIdentityProviderUrlQueryParameter() {
		cut = new JwtIssuerValidator(Collections.singletonList("accounts400.ondemand.com"));
		when(token.getClaimAsString(ISSUER)).thenReturn("https://test.accounts400.ondemand.com");
		when(token.getClaimAsString(IAS_ISSUER)).thenReturn("https://otherDomain.org?accounts400.ondemand.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer is not trusted because 'ias_iss' claim 'https://otherDomain.org?accounts400.ondemand.com' does not provide a valid URI."));
	}

	@Test
	public void validationFails_whenIssuerIsEmpty() {
		when(token.getClaimAsString(ISSUER)).thenReturn(" ");
		when(token.getClaimAsString(IAS_ISSUER)).thenReturn("https://test.accounts400.ondemand.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Issuer validation can not be performed because Jwt token does not contain 'iss' claim."));
	}

	@Test
	public void validationFails_whenIssuerIsNull() {
		when(token.getClaimAsString(ISSUER)).thenReturn(null);
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Issuer validation can not be performed because Jwt token does not contain 'iss' claim."));
	}

	@Test
	public void validationFails_whenIssuerIsNotAValidUri() {
		when(token.getClaimAsString(ISSUER)).thenReturn("\0://myauth.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because"));
	}

	@Test
	public void validationFails_whenIssuerContainsQueryParameters() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://subdomain.accounts400.ondemand.com?a=b");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because"));
	}

	@Test
	public void validationFails_whenIssuerContainsFragment() {
		when(token.getHeaderParameterAsString(JWKS_URL))
				.thenReturn("https://subdomain.myauth.ondemand.com/token_keys#token_keys");
		when(token.getClaimAsString(IAS_ISSUER)).thenReturn("https://otherDomain.accounts400.ondemand.com");

		when(token.getClaimAsString(ISSUER)).thenReturn("https://subdomain.accounts400.ondemand.com#anyFragment_keys");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because"));
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

	@Test
	public void validationSucceeds_forCustomDomain() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://nestle.com");
		when(token.getClaimAsString(IAS_ISSUER)).thenReturn("https://otherDomain.accounts400.ondemand.com");

		ValidationResult validationResult = cut.validate(token);
		assertTrue(validationResult.isValid());
	}

	@Test
	public void validationSucceeds_withEmptyIasIssuer() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://otherDomain.accounts400.ondemand.com");
		when(token.getClaimAsString(IAS_ISSUER)).thenReturn("");

		ValidationResult validationResult = cut.validate(token);
		assertTrue(validationResult.isValid());
	}

}
