package com.sap.cloud.security.token.validation.validators;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.junit.Test;
import org.mockito.Mockito;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;

public class CombiningValidatorTest {

	private static final String FIRST_ERROR_MESSAGE = "firstMessage";
	private static final String SECOND_ERROR_MESSAGE = "secondMessage";

	@Test
	public void validate_containsNoValidators_validResult() {
		Validator<Token> combiningValidator = CombiningValidator.builder().build();

		ValidationResult validationResult = combiningValidator.validate(null);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void validate_twoValidValidators_validResult() {
		Validator<Token> combiningValidator = CombiningValidator.builder()
				.with(validValidator())
				.with(validValidator())
				.build();

		ValidationResult validationResult = combiningValidator.validate(null);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void validate_twoInvalidValidators_invalidResult() {
		Validator<Token> combiningValidator = CombiningValidator.builder()
				.with(invalidValidator())
				.with(invalidValidator())
				.build();

		ValidationResult validationResult = combiningValidator.validate(null);

		assertThat(validationResult.isErroneous()).isTrue();
	}

	@Test
	public void validate_twoInvalidValidators_containsOnlyOneErrorMessages() {
		Validator<Token> combiningValidator = CombiningValidator.builder()
				.with(validValidator())
				.with(invalidValidator(FIRST_ERROR_MESSAGE))
				.with(invalidValidator(SECOND_ERROR_MESSAGE)).build();

		String error = combiningValidator.validate(null).getErrorDescription();

		assertThat(error).isEqualTo(FIRST_ERROR_MESSAGE);
	}

	@Test
	public void build_xsuaaCombiningValidator() throws URISyntaxException, IOException {
		OAuth2ServiceConfiguration configuration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(configuration.getUrl()).thenReturn(new URI("https://my.auth.com"));
		when(configuration.getDomain()).thenReturn("auth.com");
		when(configuration.getClientId()).thenReturn("sb-test-app!t123");
		when(configuration.getProperty(CFConstants.XSUAA.APP_ID)).thenReturn("test-app!t123");

		CombiningValidator combiningValidator = CombiningValidator.builderFor(configuration).build();
		String allValidators = combiningValidator.toString();
		assertThat(allValidators).contains("JwtTimestampValidator");
		assertThat(allValidators).contains("XsuaaJwtIssuerValidator");
		assertThat(allValidators).contains("XsuaaJwtAudienceValidator");
		assertThat(allValidators).contains("JwtSignatureValidator");
	}

	private Validator<Token> validValidator() {
		return (obj) -> ValidationResults.createValid();
	}

	private Validator<Token> invalidValidator() {
		return invalidValidator(FIRST_ERROR_MESSAGE);
	}

	private Validator<Token> invalidValidator(String errorMessage) {
		return (obj) -> ValidationResults.createInvalid(errorMessage);
	}

}