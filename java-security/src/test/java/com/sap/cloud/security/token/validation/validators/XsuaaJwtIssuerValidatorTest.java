package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static com.sap.cloud.security.token.TokenHeader.JWKS_URL;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

public class XsuaaJwtIssuerValidatorTest {
	private XsuaaJwtIssuerValidator cut;
	private Token token;

	@Before
	public void setup() {
		cut = new XsuaaJwtIssuerValidator("myauth.ondemand.com");
		token = Mockito.mock(Token.class);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new XsuaaJwtIssuerValidator(null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("XsuaaJwtIssuerValidator", "uaaDomain");

		assertThatThrownBy(() -> {
			new XsuaaJwtIssuerValidator(" ");
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("XsuaaJwtIssuerValidator", "uaaDomain");
	}

	@Test
	public void tokenIssuerMatchesIdentityServiceDomain() {
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn("https://subdomain.myauth.ondemand.com");
		assertThat(cut.validate(token).isValid(), is(true));
	}

	@Test
	public void validationFails_whenTokenIssuerDoesNotMatchIdentityServiceDomain() {
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn("https://subdomain.any.ondemand.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer is not trusted because 'jku' 'https://subdomain.any.ondemand.com' does not match uaa domain 'myauth.ondemand.com' of the identity service."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsEmpty() {
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn(" ");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer validation can not be performed because Jwt token does not contain 'jku' header parameter."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsNull() {
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn(null);
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer validation can not be performed because Jwt token does not contain 'jku' header parameter."));
	}

	@Test
	public void validationFails_whenTokenIssuerIsNotAValidUri() {
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn("\0://myauth.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because"));
	}
}
