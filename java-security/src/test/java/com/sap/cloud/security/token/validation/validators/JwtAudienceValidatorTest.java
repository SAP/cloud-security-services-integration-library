package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtAudienceValidatorTest {

	private Token token;

	@Before
	public void setUp() {
		token = Mockito.mock(Token.class);
		Mockito.when(token.getAudiences()).thenReturn(Arrays.asList("client", "foreignclient", "thirdclient"));
	}

	@Test
	public void validate_tokenAudienceMatchesClientId() {
		ValidationResult result = new JwtAudienceValidator("client")
				.validate(token);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void validate_tokenAudienceMatchesForeignClientId() {
		ValidationResult result = new JwtAudienceValidator("any")
				.configureAnotherServiceInstance("foreignclient")
				.validate(token);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void validationFails_when_NoTokenAudienceMatches() {
		ValidationResult result = new JwtAudienceValidator("any")
				.configureAnotherServiceInstance("anyother")
				.validate(token);

		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription())
				.isEqualTo("Jwt token audience [client, foreignclient, thirdclient] is not issued for these clientIds: [any, anyother].");
	}

	@Test
	public void validationFails_when_TokenAudiencesAreEmpty() {
		Mockito.when(token.getAudiences()).thenReturn(Collections.emptyList());

		ValidationResult result = new JwtAudienceValidator("any")
				.validate(token);

		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription())
				.isEqualTo("Jwt token audience [] is not issued for these clientIds: [any].");
	}


}