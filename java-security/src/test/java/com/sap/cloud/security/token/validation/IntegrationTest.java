package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.validators.CombiningValidator;
import com.sap.cloud.security.token.validation.validators.TokenValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;
import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class IntegrationTest {

	@Test
	public void validationFails_withXsuaaCombiningValidator() throws URISyntaxException, IOException {
		OAuth2ServiceConfiguration configuration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(configuration.getUrl()).thenReturn(new URI("https://my.auth.com"));
		when(configuration.getDomain()).thenReturn("auth.com");
		when(configuration.getClientId()).thenReturn("sb-test-app!t123");
		when(configuration.getProperty(CFConstants.XSUAA.APP_ID)).thenReturn("test-app!t123");
		when(configuration.getServiceName()).thenReturn(Service.XSUAA.getName());

		CombiningValidator<Token> tokenValidator = TokenValidatorBuilder.createFor(configuration).build();

		Token xsuaaToken = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8));
		ValidationResult result = tokenValidator.validate(xsuaaToken);
		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription()).contains("Jwt expired at 2019-10-26T03:32:49Z");
	}

	@Test
	@Ignore // TODO
	public void validate_withXsuaaCombiningValidator_whenOAuthServerIsMocked() throws IOException {
		Properties oldProperties = System.getProperties();
		System.setProperty("VCAP_SERVICES", IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", StandardCharsets.UTF_8));

		OAuth2ServiceConfiguration configuration = Environments.getCurrentEnvironment().getXsuaaServiceConfiguration();

		OAuth2TokenKeyService tokenKeyService = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyService.retrieveTokenKeys(any())).thenReturn(JsonWebKeySetFactory.createFromJson(
				IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8)));

		CombiningValidator<Token> combiningValidator = TokenValidatorBuilder.createFor(configuration)
				.withOAuth2TokenKeyService(tokenKeyService)
				.build();

		Token xsuaaToken = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8));

		ValidationResult result = combiningValidator.validate(xsuaaToken);
		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription())
				.contains("Error retrieving Json Web Keys from Identity Service (https://my.auth.com/token_keys)");

		System.setProperties(oldProperties);
	}
}
