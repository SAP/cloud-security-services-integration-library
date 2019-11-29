package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class TokenValidatorBuilderTest {

	public static final Token TOKEN = mock(Token.class);

	@Test
	public void with_addedValidator_isUsed() {
		TokenValidator myValidatorMock = createTokenValidatorMock();

		TokenValidatorBuilder.create().with(myValidatorMock).build().validate(TOKEN);

		verify(myValidatorMock, times(1)).validate(TOKEN);
	}

	@Test
	public void withAudienceValidator_overridesXsuaaJwtAudienceValidator() throws URISyntaxException {
		TokenValidator tokenValidatorMock = createTokenValidatorMock();
		List<Validator<Token>> validators = TokenValidatorBuilder.createFor(createMockConfiguration())
				.withAudienceValidator(tokenValidatorMock)
				.build()
				.getValidators();
		assertThat(validators).contains(tokenValidatorMock)
				.doesNotHaveAnyElementsOfTypes(XsuaaJwtAudienceValidator.class);
	}

	@Test
	public void build_withConfiguration_containsAllDefaultValidators() throws URISyntaxException {
		OAuth2ServiceConfiguration configuration = createMockConfiguration();

		List<Validator<Token>> validators = TokenValidatorBuilder.createFor(configuration).build().getValidators();

		assertThat(validators)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.hasAtLeastOneElementOfType(XsuaaJwtAudienceValidator.class)
				.hasAtLeastOneElementOfType(XsuaaJwtIssuerValidator.class)
				.hasAtLeastOneElementOfType(JwtSignatureValidator.class);
	}

	private OAuth2ServiceConfiguration createMockConfiguration() throws URISyntaxException {
		OAuth2ServiceConfiguration configuration = mock(OAuth2ServiceConfiguration.class);
		when(configuration.getUrl()).thenReturn(new URI("https://my.auth.com"));
		when(configuration.getDomain()).thenReturn("auth.com");
		when(configuration.getClientId()).thenReturn("sb-test-app!t123");
		when(configuration.getProperty(CFConstants.XSUAA.APP_ID)).thenReturn("test-app!t123");
		when(configuration.getService()).thenReturn(Service.XSUAA);
		return configuration;
	}

	private TokenValidator createTokenValidatorMock() {
		TokenValidator tokenValidatorMock = mock(TokenValidator.class);
		when(tokenValidatorMock.validate(TOKEN)).thenReturn(ValidationResults.createValid());
		return tokenValidatorMock;
	}

	private interface TokenValidator extends Validator<Token> {

	}
}