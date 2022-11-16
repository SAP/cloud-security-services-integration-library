/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.*;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class JwtValidatorBuilderTest {

	OAuth2ServiceConfigurationBuilder xsuaaConfigBuilder = OAuth2ServiceConfigurationBuilder.forService(XSUAA)
			.withDomains("auth.com")
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
		JwtValidatorBuilder builder_3 = JwtValidatorBuilder.getInstance(xsuaaConfigBuilder.build());
		assertThat(builder_1).isSameAs(builder_2);
		assertThat(builder_1).isSameAs(builder_3);
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
				.hasAtLeastOneElementOfType(XsuaaJkuValidator.class)
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
				.doesNotHaveAnyElementsOfTypes(XsuaaJkuValidator.class);
	}

	@Test
	public void buildIas_containsAllDefaultValidators() {
		OAuth2ServiceConfigurationBuilder iasConfigBuilder = OAuth2ServiceConfigurationBuilder.forService(IAS)
				.withDomains("app.auth.com")
				.withClientId("T0123456");

		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(iasConfigBuilder.build())
				.build()
				.getValidators();

		assertThat(validators)
				.hasSize(4)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.hasAtLeastOneElementOfType(JwtAudienceValidator.class)
				.hasAtLeastOneElementOfType(JwtSignatureValidator.class)
				.hasAtLeastOneElementOfType(JwtIssuerValidator.class);
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

	@Test
	public void configureOtherServiceInstances() {
		Collection clientIds = new ArrayList();
		JwtAudienceValidator audienceValidator;

		OAuth2ServiceConfiguration xsuaaConfig1 = xsuaaConfigBuilder.build();
		OAuth2ServiceConfiguration xsuaaConfig2 = OAuth2ServiceConfigurationBuilder.forService(XSUAA)
				.withClientId("sb-test-app2!b222").build();
		OAuth2ServiceConfiguration xsuaaConfig3 = OAuth2ServiceConfigurationBuilder.forService(XSUAA)
				.withClientId("sb-test-app3!b333").build();

		clientIds.add(xsuaaConfig1.getClientId());
		clientIds.add(xsuaaConfig2.getClientId());
		clientIds.add(xsuaaConfig3.getClientId());

		CombiningValidator<Token> combiningValidator = JwtValidatorBuilder
				.getInstance(xsuaaConfig1)
				.configureAnotherServiceInstance(xsuaaConfig2)
				.configureAnotherServiceInstance(xsuaaConfig3)
				.build();

		for (Validator validator : combiningValidator.getValidators()) {
			if (validator instanceof JwtAudienceValidator) {
				assertThat(((JwtAudienceValidator) validator).getTrustedClientIds()).containsAll(clientIds);
				return;
			}
		}
		Assert.fail("No JwtAudienceValidator found that contains all clientIds!"); // should never be called
	}

}