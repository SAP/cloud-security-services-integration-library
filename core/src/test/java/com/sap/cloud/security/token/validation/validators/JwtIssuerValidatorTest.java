package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.TokenClaims.*;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.is;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import com.sap.cloud.security.token.validation.ValidationResult;

public class JwtIssuerValidatorTest {

	private JwtIssuerValidator cut;

	@Before
	public void setup() {
		cut = new JwtIssuerValidator("accounts400.ondemand.com");
	}

	@Test
	public void tokenIssuerMatchesIdentityServiceDomain() {
		Token token = Mockito.mock(TokenImpl.class);
		when(token.getClaimAsString(ISSUER)).thenReturn("https://subdomain.accounts400.ondemand.com");
		assertThat(cut.validate(token).isValid(), is(true));
	}

	@Test
	public void validationFails_whenTokenIssuerDoesNotMatchIdentityServiceDomain() {
		Token token = Mockito.mock(TokenImpl.class);
		when(token.getClaimAsString(ISSUER)).thenReturn("https://subdomain.accounts300.ondemand.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(false));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because 'iss' 'https://subdomain.accounts300.ondemand.com' does not match domain 'accounts400.ondemand.com' of the identity service."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsEmpty() {
		Token token = Mockito.mock(TokenImpl.class);
		when(token.getClaimAsString(ISSUER)).thenReturn(" ");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(false));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer validation can not be performed because JWT token does not contain 'iss' claim."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsNull() {
		Token token = Mockito.mock(TokenImpl.class);
		when(token.getClaimAsString(ISSUER)).thenReturn(null);
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(false));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer validation can not be performed because JWT token does not contain 'iss' claim."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsNotAValidUri() {
		Token token = Mockito.mock(TokenImpl.class);
		when(token.getClaimAsString(ISSUER)).thenReturn("\0://myauth.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(false));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because"));
	}

}
