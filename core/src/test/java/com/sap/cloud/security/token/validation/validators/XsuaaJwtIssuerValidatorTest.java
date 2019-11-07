package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.TokenHeader.*;
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

public class XsuaaJwtIssuerValidatorTest {
	private XsuaaJwtIssuerValidator cut;

	@Before
	public void setup() {
		cut = new XsuaaJwtIssuerValidator("myauth.ondemand.com");
	}

	@Test
	public void tokenIssuerMatchesIdentityServiceDomain() {
		Token token = Mockito.mock(TokenImpl.class);
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn("https://subdomain.myauth.ondemand.com");
		assertThat(cut.validate(token).isValid(), is(true));
	}

	@Test
	public void validationFails_whenTokenIssuerDoesNotMatchIdentityServiceDomain() {
		Token token = Mockito.mock(TokenImpl.class);
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn("https://subdomain.any.ondemand.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(false));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because 'jku' 'https://subdomain.any.ondemand.com' does not match uaa domain 'myauth.ondemand.com' of the identity service."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsEmpty() {
		Token token = Mockito.mock(TokenImpl.class);
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn(" ");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(false));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer validation can not be performed because JWT token does not contain 'jku' header parameter."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsNull() {
		Token token = Mockito.mock(TokenImpl.class);
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn(null);
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(false));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer validation can not be performed because JWT token does not contain 'jku' header parameter."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsNotAValidUri() {
		Token token = Mockito.mock(TokenImpl.class);
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn("\0://myauth.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isValid(), is(false));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because"));
	}
}
