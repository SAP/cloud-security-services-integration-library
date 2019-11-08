package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.MockTokenBuilder;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;

import org.apache.commons.io.IOUtils;
import org.assertj.core.api.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;

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

		assertThat(validationResult.isValid()).isFalse();
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
	public void validate_twoInvalidValidatorsWithValidateAll_containsBothErrorMessages() {
		CombiningValidator<Token> combiningValidator = CombiningValidator.builder()
				.with(validValidator())
				.with(invalidValidator(FIRST_ERROR_MESSAGE))
				.with(invalidValidator(SECOND_ERROR_MESSAGE))
				.with(validValidator())
				.validateAll()
				.build();

		ValidationResult result = combiningValidator.validate(null);
		assertThat(result.getErrorDescription()).isEqualTo("2 out of 4 validators reported an error. Please see detailed error descriptions.");
		assertThat(result.isValid()).isEqualTo(false);

		List<String> errorMessages = combiningValidator.getAllErrorDescriptions();
		assertThat(errorMessages).containsExactly(FIRST_ERROR_MESSAGE, SECOND_ERROR_MESSAGE);
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

	@Test
	public void validationFails_withXsuaaCombiningValidator_whenOAuthServerIsUnavailable() throws URISyntaxException, IOException {
		OAuth2ServiceConfiguration configuration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(configuration.getUrl()).thenReturn(new URI("https://my.auth.com"));
		when(configuration.getDomain()).thenReturn("auth.com");
		when(configuration.getClientId()).thenReturn("sb-test-app!t123");
		when(configuration.getProperty("appId")).thenReturn("test-app!t123");

		Validator combiningValidator = CombiningValidator.builderFor(configuration).build();

		Token xsuaaToken = new TokenImpl(IOUtils.resourceToString("/xsuaaAccessTokenRSA256.txt", StandardCharsets.UTF_8));
		ValidationResult result = combiningValidator.validate(xsuaaToken);
		assertThat(result.isValid()).isFalse();
		assertThat(result.getErrorDescription()).contains("Error retrieving Json Web Keys from Identity Service (https://my.auth.com/token_keys)");
	}

	@Test
	public void validate_withXsuaaCombiningValidator_whenOAuthServerIsMocked() throws URISyntaxException, IOException {
		OAuth2ServiceConfiguration configuration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(configuration.getUrl()).thenReturn(new URI("https://my.auth.com"));
		when(configuration.getDomain()).thenReturn("auth.com");
		when(configuration.getClientId()).thenReturn("sb-test-app!t123");
		when(configuration.getProperty("appId")).thenReturn("test-app!t123");

		OAuth2TokenKeyService tokenKeyService = Mockito.mock(OAuth2TokenKeyService.class);
		Validator combiningValidator = CombiningValidator.builderFor(configuration)
				.withOAuth2TokenKeyService(tokenKeyService).build();

		Token xsuaaToken = new TokenImpl(IOUtils.resourceToString("/xsuaaAccessTokenRSA256.txt", StandardCharsets.UTF_8));
		ValidationResult result = combiningValidator.validate(xsuaaToken);
		assertThat(result.isValid()).isFalse();
		assertThat(result.getErrorDescription()).contains("Error retrieving Json Web Keys from Identity Service (https://my.auth.com/token_keys)");
	}

}