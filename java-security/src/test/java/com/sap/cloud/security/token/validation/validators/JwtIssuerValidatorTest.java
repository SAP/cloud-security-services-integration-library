package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static com.sap.cloud.security.token.TokenClaims.ISSUER;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

public class JwtIssuerValidatorTest {

	private JwtIssuerValidator cut;
	private Token token;

	@Before
	public void setup() {
		cut = new JwtIssuerValidator("accounts400.ondemand.com");
		token = Mockito.mock(Token.class);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new JwtIssuerValidator(null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("domain");

		assertThatThrownBy(() -> {
			new JwtIssuerValidator(" ");
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("domain");
	}

	@Test
	public void tokenIssuerMatchesIdentityServiceDomain() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://subdomain.accounts400.ondemand.com");
		assertThat(cut.validate(token).isValid(), is(true));
	}

	@Test
	public void validationFails_whenTokenIssuerDoesNotMatchIdentityServiceDomain() {
		when(token.getClaimAsString(ISSUER)).thenReturn("https://subdomain.accounts300.ondemand.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith(
				"Issuer is not trusted because 'iss' 'https://subdomain.accounts300.ondemand.com' does not match domain 'accounts400.ondemand.com' of the identity service."));
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
		Token token = Mockito.mock(Token.class);
		when(token.getClaimAsString(ISSUER)).thenReturn("\0://myauth.com");
		ValidationResult validationResult = cut.validate(token);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(), startsWith("Issuer is not trusted because"));
	}

}
