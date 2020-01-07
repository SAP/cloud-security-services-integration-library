package com.sap.cloud.security.token.validation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.mockito.Mockito;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;

public class IntegrationTest {

	@Test
	public void validationFails_withXsuaaCombiningValidator() throws URISyntaxException, IOException {
		OAuth2ServiceConfiguration configuration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(configuration.getUrl()).thenReturn(new URI("https://my.auth.com"));
		when(configuration.getClientId()).thenReturn("sb-test-app!t123");
		when(configuration.getProperty(CFConstants.XSUAA.APP_ID)).thenReturn("test-app!t123");
		when(configuration.getProperty(CFConstants.XSUAA.UAA_DOMAIN)).thenReturn("auth.com");
		when(configuration.getService()).thenReturn(Service.XSUAA);

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration).build();

		Token xsuaaToken = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8), "test-app!t123");
		ValidationResult result = tokenValidator.validate(xsuaaToken);
		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription()).contains("Jwt expired at 2019-10-26T03:32:49Z");
	}
}
