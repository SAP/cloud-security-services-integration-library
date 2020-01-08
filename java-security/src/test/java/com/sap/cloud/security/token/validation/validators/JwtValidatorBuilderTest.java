package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants.XSUAA;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import org.junit.Ignore;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class JwtValidatorBuilderTest {

	public static final Token TOKEN = mock(Token.class);

	@Test
	public void sameServiceConfiguration_getSameInstance() throws URISyntaxException {
		TokenValidator tokenValidatorMock = createTokenValidatorMock();
		OAuth2ServiceConfiguration configuration = createMockConfiguration();
		JwtValidatorBuilder builder_1 = JwtValidatorBuilder.getInstance(configuration);
		JwtValidatorBuilder builder_2 = JwtValidatorBuilder.getInstance(configuration);
		assertThat(builder_1).isSameAs(builder_2);
	}

	@Test
	public void withAudienceValidator_overridesXsuaaJwtAudienceValidator() throws URISyntaxException {
		TokenValidator tokenValidatorMock = createTokenValidatorMock();
		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(createMockConfiguration())
				.withAudienceValidator(tokenValidatorMock)
				.build()
				.getValidators();
		assertThat(validators).contains(tokenValidatorMock)
				.doesNotHaveAnyElementsOfTypes(XsuaaJwtAudienceValidator.class);
	}

	@Test
	public void build_containsAllDefaultValidators() throws URISyntaxException {
		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(createMockConfiguration()).build()
				.getValidators();

		assertThat(validators)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.hasAtLeastOneElementOfType(XsuaaJwtAudienceValidator.class)
				.hasAtLeastOneElementOfType(XsuaaJwtIssuerValidator.class)
				.hasAtLeastOneElementOfType(JwtSignatureValidator.class);
	}

	@Test
	public void buildWithAnotherValidator_containsAddedValidator() throws URISyntaxException {
		TokenValidator tokenValidatorMock = createTokenValidatorMock();

		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(createMockConfiguration())
				.with(tokenValidatorMock)
				.build()
				.getValidators();

		assertThat(validators)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.contains(tokenValidatorMock);
	}

	private OAuth2ServiceConfiguration createMockConfiguration() throws URISyntaxException {
		OAuth2ServiceConfiguration configuration = mock(OAuth2ServiceConfiguration.class);
		when(configuration.getUrl()).thenReturn(new URI("https://my.auth.com"));
		when(configuration.getClientId()).thenReturn("sb-test-app!t123");
		when(configuration.getProperty(XSUAA.APP_ID)).thenReturn("test-app!t123");
		when(configuration.getProperty(XSUAA.UAA_DOMAIN)).thenReturn("auth.com");
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