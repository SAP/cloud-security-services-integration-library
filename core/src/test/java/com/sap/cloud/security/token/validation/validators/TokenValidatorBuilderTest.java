package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.cf.CFService;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import com.sun.jdi.VMMismatchException;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class TokenValidatorBuilderTest {

	public static final Token TOKEN = mock(Token.class);

	private interface TokenValidator extends Validator<Token> {

	}
	@Test
	public void with_addedvalidator_isUsed() {
		TokenValidator myValidatorMock = createTokenValidatorMock();

		TokenValidatorBuilder.create().with(myValidatorMock).build().validate(TOKEN);

		verify(myValidatorMock, times(1)).validate(TOKEN);
	}

	@Test
	public void withAudienceValidator_overridesXsuaaJwtAudienceValidator() throws URISyntaxException {
		// TODO 20.11.19 c5295400: Test over strings..?
		String validatorsString = TokenValidatorBuilder.createFor(createMockConfiguration())
				.withAudienceValidator(createTokenValidatorMock())
				.build()
				.toString();
		assertThat(validatorsString).doesNotContain("XsuaaJwtAudienceValidator");
	}


	@Test
	public void build_withConfiguration_containsDefaultValidators() throws URISyntaxException {
		OAuth2ServiceConfiguration configuration = createMockConfiguration();

		Validator<Token> combiningValidator = TokenValidatorBuilder.createFor(configuration).build();
		String allValidators = combiningValidator.toString();
		assertThat(allValidators).contains("JwtTimestampValidator");
		assertThat(allValidators).contains("XsuaaJwtIssuerValidator");
		assertThat(allValidators).contains("XsuaaJwtAudienceValidator");
		assertThat(allValidators).contains("JwtSignatureValidator");
		when(configuration.getServiceName()).thenReturn(CFService.XSUAA.getName());
	}

	private OAuth2ServiceConfiguration createMockConfiguration() throws URISyntaxException {
		OAuth2ServiceConfiguration configuration = mock(OAuth2ServiceConfiguration.class);
		when(configuration.getUrl()).thenReturn(new URI("https://my.auth.com"));
		when(configuration.getDomain()).thenReturn("auth.com");
		when(configuration.getClientId()).thenReturn("sb-test-app!t123");
		when(configuration.getProperty(CFConstants.XSUAA.APP_ID)).thenReturn("test-app!t123");
		when(configuration.getServiceName()).thenReturn(CFService.XSUAA.getName());
		return configuration;
	}

	private TokenValidator createTokenValidatorMock() {
		TokenValidator tokenValidatorMock = mock(TokenValidator.class);
		when(tokenValidatorMock.validate(TOKEN)).thenReturn(ValidationResults.createValid());
		return tokenValidatorMock;
	}
}