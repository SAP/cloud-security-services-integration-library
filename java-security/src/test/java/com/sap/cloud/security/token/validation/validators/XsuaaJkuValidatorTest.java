package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static com.sap.cloud.security.token.TokenHeader.JWKS_URL;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

public class XsuaaJkuValidatorTest {
	private XsuaaJkuValidator cut;
	private Token token;

	@Before
	public void setup() {
		cut = new XsuaaJkuValidator("myauth.ondemand.com");
		token = Mockito.mock(Token.class);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new XsuaaJkuValidator(null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("XsuaaJkuValidator", "uaaDomain");

		assertThatThrownBy(() -> {
			new XsuaaJkuValidator(" ");
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContainingAll("XsuaaJkuValidator", "uaaDomain");
	}

	@Test
	public void jwksMatchesIdentityServiceDomain() {
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn("https://subdomain.myauth.ondemand.com/token_keys");
		assertThat(cut.validate(token).isValid(), is(true));
	}

	@Test
	public void validationFails_whenJwksDoesNotMatchIdentityServiceDomain() {
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn("https://subdomain.any.ondemand.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer is not trusted because 'jku' 'https://subdomain.any.ondemand.com' does not match uaa domain 'myauth.ondemand.com' of the identity service."));
	}

	@Test
	public void validationFails_whenJwksIsEmpty() {
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn(" ");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer validation can not be performed because Jwt token does not contain 'jku' header parameter."));
	}

	@Test
	public void validationFails_whenJwksIsNull() {
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn(null);
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer validation can not be performed because Jwt token does not contain 'jku' header parameter."));
	}

	@Test
	public void validationFails_whenJwksIsNotAValidUri() {
		when(token.getHeaderParameterAsString(JWKS_URL)).thenReturn("\0://myauth.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				containsString("Jwt token does not contain a valid uri as 'jku' header parameter"));
	}

	@Test
	public void validationFails_whenJwksDoesNotContainAValidPath() {
		when(token.getHeaderParameterAsString(JWKS_URL))
				.thenReturn("https://subdomain.myauth.ondemand.com/wrong_endpoint");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				containsString("Jwt token does not contain a valid 'jku' header parameter"));
	}

	@Test
	public void validationFails_whenJwksContainsQueryParameters() {
		when(token.getHeaderParameterAsString(JWKS_URL))
				.thenReturn("https://subdomain.myauth.ondemand.com/token_keys?a=b");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				containsString("Jwt token does not contain a valid 'jku' header parameter"));
	}

	@Test
	public void validationFails_whenJwksContainsFragment() {
		when(token.getHeaderParameterAsString(JWKS_URL))
				.thenReturn("https://subdomain.myauth.ondemand.com/token_keys#token_keys");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				containsString("Jwt token does not contain a valid 'jku' header parameter"));
	}

	@Test
	public void validationFails_whenJkuHasNonTrustedHost() {
		when(token.getHeaderParameterAsString(JWKS_URL))
				.thenReturn("http://myauth.ondemand.com\\@malicious.ondemand.com/token_keys");
		assertThat(cut.validate(token).isValid(), is(false));
		when(token.getHeaderParameterAsString(JWKS_URL))
				.thenReturn("http://myauth.ondemand.com@malicious.ondemand.com/token_keys");
		assertThat(cut.validate(token).isValid(), is(false));
		when(token.getHeaderParameterAsString(JWKS_URL))
				.thenReturn("http://malicious.ondemand.com/token_keys///myauth.ondemand.com/token_keys");
		assertThat(cut.validate(token).isValid(), is(false));
	}
}
