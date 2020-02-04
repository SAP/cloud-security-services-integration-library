package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.List;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class JwtValidatorBuilderTest {

	OAuth2ServiceConfigurationBuilder xsuaaConfigBuilder = OAuth2ServiceConfigurationBuilder.forService(XSUAA)
			.withProperty(CFConstants.XSUAA.UAA_DOMAIN, "auth.com")
			.withProperty(CFConstants.XSUAA.APP_ID, "test-app!t123")
			.withClientId("sb-test-app!t123");

	@Before
	public void setUp() {
		Mockito.mockitoSession().initMocks();
	}

	@Test
	public void sameServiceConfiguration_getSameInstance() {
		TokenTestValidator.createValid();
		OAuth2ServiceConfiguration configuration = xsuaaConfigBuilder.build();
		JwtValidatorBuilder builder_1 = JwtValidatorBuilder.getInstance(configuration);
		JwtValidatorBuilder builder_2 = JwtValidatorBuilder.getInstance(configuration);
		assertThat(builder_1).isSameAs(builder_2);
	}

	@Test
	public void withAudienceValidator_overridesXsuaaJwtAudienceValidator() {
		TokenTestValidator validator = TokenTestValidator.createValid();
		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(xsuaaConfigBuilder.build())
				.withAudienceValidator(validator)
				.build()
				.getValidators();
		assertThat(validators).contains(validator)
				.doesNotHaveAnyElementsOfTypes(JwtAudienceValidator.class);
	}

	@Test
	public void build_containsAllDefaultValidators() {
		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(xsuaaConfigBuilder.build()).build()
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
				.getInstance(xsuaaConfigBuilder.runInLegacyMode(true).build())
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
	public void buildWithAnotherValidator_containsAddedValidator() {
		TokenTestValidator tokenValidator = TokenTestValidator.createValid();

		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(xsuaaConfigBuilder.build())
				.with(tokenValidator)
				.build()
				.getValidators();

		assertThat(validators)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.contains(tokenValidator);
	}

}