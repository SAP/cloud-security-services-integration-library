package com.sap.cloud.security.token.validation;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.GregorianCalendar;
import java.util.Map;

import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.util.HttpClientTestFactory;
import com.sun.tools.javac.util.List;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;

public class IntegrationTest {

	public static final Instant NO_EXPIRE_DATE = new GregorianCalendar(2190, 11, 31).getTime().toInstant();

	CloseableHttpClient mockHttpClient;

	@Before
	public void setup() throws IOException {
		mockHttpClient = Mockito.mock(CloseableHttpClient.class);

		CloseableHttpResponse response = HttpClientTestFactory
				.createHttpResponse(IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8));
		when(mockHttpClient.execute(any(HttpGet.class))).thenReturn(response);
	}

	@Test
	public void validationFails_withXsuaaCombiningValidator() throws URISyntaxException, IOException {
		String vcapServices = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
		JsonObject serviceJsonObject = new DefaultJsonObject(vcapServices).getJsonObjects(Service.XSUAA.getCFName()).get(0);
		Map<String, String> credentialsMap = serviceJsonObject.getJsonObject(CFConstants.CREDENTIALS).getKeyValueMap();

		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withProperties(credentialsMap)
				.build();

		CombiningValidator<Token> tokenValidator =
				JwtValidatorBuilder.getInstance(configuration)
						.withHttpClient(mockHttpClient)
						.build();

		Token xsuaaToken = spy(new XsuaaToken(
				IOUtils.resourceToString("/xsuaaUserAccessTokenRSA256.txt", StandardCharsets.UTF_8)));
		when(xsuaaToken.getExpiration()).thenReturn(NO_EXPIRE_DATE);
		when(xsuaaToken.getClaimAsStringList(TokenClaims.AUDIENCE)).thenReturn(List.from(new String[]{"clientId"}));

		ValidationResult result = tokenValidator.validate(xsuaaToken);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void xsaTokenValidationSucceeds_withXsuaaCombiningValidator() throws IOException {
		String XsaVcapServices = IOUtils.resourceToString("/vcapXsuaaXsaSingleBinding.json", UTF_8);
		JsonObject serviceJsonObject = new DefaultJsonObject(XsaVcapServices).getJsonObjects(Service.XSUAA.getCFName()).get(0);
		Map<String, String> credentialsMap = serviceJsonObject.getJsonObject(CFConstants.CREDENTIALS).getKeyValueMap();

		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withProperties(credentialsMap)
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, "xsa-a272d86a-0f74-448c-93d1-6b78903d1543")// TODO
				.build();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration)
				.enableLegacyMode()
				.withHttpClient(mockHttpClient)
				.build();

		XsuaaToken xsaToken = spy(new XsuaaToken(
				IOUtils.resourceToString("/xsuaaXsaAccessTokenRSA256_signedWithVerificationKey.txt", UTF_8)));
		when(xsaToken.getExpiration()).thenReturn(NO_EXPIRE_DATE);

		ValidationResult result = tokenValidator.validate(xsaToken);
		assertThat(result.isValid()).isTrue();
	}
}
