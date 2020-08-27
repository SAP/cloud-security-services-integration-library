package com.sap.cloud.security.test.integration;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import org.apache.commons.io.IOUtils;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

public class XsuaaEnvironmentIntegrationTest {

	@ClassRule
	public static SecurityTestRule rule = SecurityTestRule.getInstance(Service.XSUAA)
			.setKeys("/publicKey.txt", "/privateKey.txt");
	@Rule
	public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

	@Test
	public void createToken_integrationTest_tokenValidation() throws IOException {
		String vcapServices = IOUtils.resourceToString("/vcap_services-multiple.json", StandardCharsets.UTF_8);
		String jwksUrl = new XsuaaDefaultEndpoints(rule.getWireMockServer().baseUrl()).getJwksUri().toString();
		vcapServices.replace("$jwksUrl", jwksUrl); // need to replace jwksUrl in VCAP_SERVICES
		environmentVariables.set("VCAP_SERVICES", vcapServices);
		Token token = rule.getPreconfiguredJwtGenerator().createToken();
		OAuth2ServiceConfiguration configuration = Environments.getCurrent().getXsuaaConfiguration();
		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration).build();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

}
