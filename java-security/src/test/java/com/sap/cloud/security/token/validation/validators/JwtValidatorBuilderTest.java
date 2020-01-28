package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.net.URISyntaxException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class JwtValidatorBuilderTest {

	public static final Token TOKEN = mock(Token.class);

	@Before
	public void setUp() {
		Mockito.mockitoSession().initMocks();
	}

	@Test
	public void sameServiceConfiguration_getSameInstance() {
		TokenTestValidator.createValid();
		OAuth2ServiceConfiguration configuration = getConfigBuilder().build();
		JwtValidatorBuilder builder_1 = JwtValidatorBuilder.getInstance(configuration);
		JwtValidatorBuilder builder_2 = JwtValidatorBuilder.getInstance(configuration);
		assertThat(builder_1).isSameAs(builder_2);
	}

	@Test
	public void withAudienceValidator_overridesXsuaaJwtAudienceValidator() {
		TokenTestValidator validator = TokenTestValidator.createValid();
		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(getConfigBuilder().build())
				.withAudienceValidator(validator)
				.build()
				.getValidators();
		assertThat(validators).contains(validator)
				.doesNotHaveAnyElementsOfTypes(JwtAudienceValidator.class);
	}

	@Test
	public void build_containsAllDefaultValidators() {
		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(getConfigBuilder().build()).build()
				.getValidators();

		assertThat(validators)
				.hasSize(4)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.hasAtLeastOneElementOfType(JwtAudienceValidator.class)
				.hasAtLeastOneElementOfType(XsuaaJwtIssuerValidator.class)
				.hasAtLeastOneElementOfType(JwtSignatureValidator.class);
	}

	@Test
	public void buildLegacy_containsAllDefaultValidators() {
		List<Validator<Token>> validators = JwtValidatorBuilder
				.getInstance(getConfigBuilder().runInLegacyMode(true).build())
				.build()
				.getValidators();

		assertThat(validators)
				.hasSize(3)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.hasAtLeastOneElementOfType(JwtAudienceValidator.class)
				.hasAtLeastOneElementOfType(JwtSignatureValidator.class)
				.doesNotHaveAnyElementsOfTypes(XsuaaJwtIssuerValidator.class);
	}

	@Test
	public void buildWithAnotherValidator_containsAddedValidator() throws URISyntaxException {
		TokenTestValidator tokenValidator = TokenTestValidator.createValid();

		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(getConfigBuilder().build())
				.with(tokenValidator)
				.build()
				.getValidators();

		assertThat(validators)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.contains(tokenValidator);
	}

	private OAuth2ServiceConfigurationBuilder getConfigBuilder() {
		return OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, "auth.com")
				.withProperty(CFConstants.XSUAA.APP_ID, "test-app!t123")
				.withClientId("sb-test-app!t123");
	}

}