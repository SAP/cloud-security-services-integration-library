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

import static com.sap.cloud.security.token.TokenClaims.ISSUER;
import static com.sap.cloud.security.token.TokenHeader.JWKS_URL;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

public class JwtIssuerValidatorTest {

	private JwtIssuerValidator cut;
	private JwtIssuerValidator cutMultiTenant;
	private Token token;

	@Before
	public void setup() {
		cut = new JwtIssuerValidator(URI.create("https://accounts400.ondemand.com"));
		cutMultiTenant = new JwtIssuerValidator("accounts400.ondemand.com");
		token = Mockito.mock(Token.class);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new JwtIssuerValidator((URI) null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("JwtIssuerValidator", "url");

		assertThatThrownBy(() -> {
			new JwtIssuerValidator((String) null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("JwtIssuerValidator", "domain");
	}

	@Test
	public void tokenIssuerMatchesIdentityProviderUrl() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://subdomain.accounts400.ondemand.com");
		assertThat(cut.validate(token).isValid(), is(true));
	}

	@Test
	public void tokenIssuerMatchesIdentityProviderDomain() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://otherdomain.accounts400.ondemand.com");
		assertThat(cutMultiTenant.validate(token).isValid(), is(true));
	}

	@Test
	public void tokenIssuerWithoutHttpSchemeMatchesIdentityProviderUrl() {
		when(token.getClaimAsString(ISSUER)).thenReturn("subdomain.accounts400.ondemand.com");

		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer is not trusted because 'iss' claim 'subdomain.accounts400.ondemand.com' does not provide a valid URI (missing http scheme)."));
	}

	@Test
	public void tokenIssuerMatchesIdentityProviderUrlWithPath() {
		cut = new JwtIssuerValidator(URI.create("https://subdomain.accounts400.ondemand.com/oauth/token"));
		when(token.getClaimAsString(ISSUER)).thenReturn("https://subdomain.accounts400.ondemand.com");
		assertThat(cut.validate(token).isValid(), is(true));
	}

	@Test
	public void validationFails_whenTokenIssuerDoesNotMatchIdentityProviderUrl() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://accounts300.ondemand.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer is not trusted because 'iss' 'https://accounts300.ondemand.com' does not match domain 'accounts400.ondemand.com' of the identity provider."));
	}

	@Test
	public void validationFails_whenTokenIssuerEndsWithIdentityProviderUrlQueryParameter() {
		cut = new JwtIssuerValidator(URI.create("https://accounts400.ondemand.com/token/oauth"));
		when(token.getClaimAsString(ISSUER)).thenReturn("https://otherDomain.org?accounts400.ondemand.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer is not trusted because 'iss' 'https://otherDomain.org?accounts400.ondemand.com' does not match domain 'accounts400.ondemand.com' of the identity provider."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsEmpty() {
		when(token.getClaimAsString(ISSUER)).thenReturn(" ");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Issuer validation can not be performed because Jwt token does not contain 'iss' claim."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsNull() {
		when(token.getClaimAsString(ISSUER)).thenReturn(null);
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Issuer validation can not be performed because Jwt token does not contain 'iss' claim."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsNotAValidUri() {
		when(token.getClaimAsString(ISSUER)).thenReturn("\0://myauth.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because"));
	}

	@Test
	public void validationFails_whenTokenIssuerContainsQueryParameters() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://subdomain.accounts400.ondemand.com?a=b");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because"));
	}

	@Test
	public void validationFails_whenTokenIssuerContainsFragment() {
		when(token.getHeaderParameterAsString(JWKS_URL))
				.thenReturn("https://subdomain.myauth.ondemand.com/token_keys#token_keys");

		when(token.getClaimAsString(ISSUER)).thenReturn("https://subdomain.accounts400.ondemand.com#anyFragment_keys");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because"));
	}

}
