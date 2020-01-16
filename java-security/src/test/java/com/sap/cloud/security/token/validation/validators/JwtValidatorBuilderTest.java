package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants.XSUAA;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.net.URISyntaxException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class JwtValidatorBuilderTest {

	public static final Token TOKEN = mock(Token.class);

	@Mock
	private CombiningValidator<Token> combiningValidatorMock;

	@Before
	public void setUp() {
		Mockito.mockitoSession().initMocks();
	}

	@Test
	public void sameServiceConfiguration_getSameInstance() throws URISyntaxException {
		TokenTestValidator.createValid();
		OAuth2ServiceConfiguration configuration = configuration();
		JwtValidatorBuilder builder_1 = JwtValidatorBuilder.getInstance(configuration);
		JwtValidatorBuilder builder_2 = JwtValidatorBuilder.getInstance(configuration);
		assertThat(builder_1).isSameAs(builder_2);
	}

	@Test
	public void withAudienceValidator_overridesXsuaaJwtAudienceValidator() throws URISyntaxException {
		TokenTestValidator validator = TokenTestValidator.createValid();
		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(configuration())
				.withAudienceValidator(validator)
				.build()
				.getValidators();
		assertThat(validators).contains(validator)
				.doesNotHaveAnyElementsOfTypes(XsuaaJwtAudienceValidator.class);
	}

	@Test
	public void build_containsAllDefaultValidators() throws URISyntaxException {
		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(configuration()).build()
				.getValidators();

		assertThat(validators)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.hasAtLeastOneElementOfType(XsuaaJwtAudienceValidator.class)
				.hasAtLeastOneElementOfType(XsuaaJwtIssuerValidator.class)
				.hasAtLeastOneElementOfType(JwtSignatureValidator.class);
	}

	@Test
	public void buildWithAnotherValidator_containsAddedValidator() throws URISyntaxException {
		TokenTestValidator tokenValidator = TokenTestValidator.createValid();

		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(configuration())
				.with(tokenValidator)
				.build()
				.getValidators();

		assertThat(validators)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.contains(tokenValidator);
	}

	@Test
	public void withValidationListener_onValidationSuccessIsCalled() throws URISyntaxException {
		ValidationListener validationListener1 = mock(ValidationListener.class);
		ValidationListener validationListener2 = mock(ValidationListener.class);
		JwtValidatorBuilder jwtValidatorBuilder = new JwtValidatorBuilder(configuration(), (validators) -> combiningValidatorMock);

		jwtValidatorBuilder
				.withValidatorListener(validationListener1)
				.withValidatorListener(validationListener2)
				.build();

		Mockito.verify(combiningValidatorMock, times(1)).registerValidationListener(validationListener1);
		Mockito.verify(combiningValidatorMock, times(1)).registerValidationListener(validationListener2);
		Mockito.verifyNoMoreInteractions(combiningValidatorMock);
	}

	private OAuth2ServiceConfiguration configuration() throws URISyntaxException {
		OAuth2ServiceConfiguration configuration = mock(OAuth2ServiceConfiguration.class);
		when(configuration.getClientId()).thenReturn("sb-test-app!t123");
		when(configuration.getProperty(XSUAA.APP_ID)).thenReturn("test-app!t123");
		when(configuration.getProperty(XSUAA.UAA_DOMAIN)).thenReturn("auth.com");
		when(configuration.getService()).thenReturn(Service.XSUAA);
		return configuration;
	}


}