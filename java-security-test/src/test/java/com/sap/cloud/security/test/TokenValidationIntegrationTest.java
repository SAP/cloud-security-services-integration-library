package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import org.apache.commons.io.IOUtils;
import org.junit.*;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.test.SecurityTestRule.DEFAULT_CLIENT_ID;
import static com.sap.cloud.security.test.SecurityTestRule.DEFAULT_DOMAIN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class TokenValidationIntegrationTest {

	private static RSAKeys keys;

	private Properties originalSystemProperties;

	@BeforeClass
	public static void setUpClass() throws Exception {
		keys = RSAKeys.fromKeyFiles("/publicKey.txt", "/privateKey.txt");
	}

	@Before
	public void setUp() {
		originalSystemProperties = System.getProperties();
	}

	@After
	public void tearDown() {
		System.setProperties(originalSystemProperties);
	}

	@Test
	public void createToken_withCorrectVerificationKey_tokenIsValid() throws IOException {
		String publicKey = IOUtils.resourceToString("/publicKey.txt", StandardCharsets.UTF_8);
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(XSUAA)
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, DEFAULT_DOMAIN)
				.withClientId(DEFAULT_CLIENT_ID)
				.withProperty("verificationkey", publicKey)
				.build();

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration)
				// mocked because we use the key from the verificationkey property here
				.withOAuth2TokenKeyService(Mockito.mock(OAuth2TokenKeyService.class))
				.build();

		Token token = JwtGenerator.getInstance(XSUAA, DEFAULT_CLIENT_ID)
				.withPrivateKey(keys.getPrivate())
				.createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void createToken_integrationTest_tokenValidation() throws IOException {
		System.setProperty("VCAP_SERVICES", IOUtils
				.resourceToString("/vcap.json", StandardCharsets.UTF_8));
		OAuth2ServiceConfiguration configuration = Environments.getCurrent().getXsuaaConfiguration();

		OAuth2TokenKeyService tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(any()))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8));

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration)
				.withOAuth2TokenKeyService(tokenKeyServiceMock)
				.build();

		Token token = JwtGenerator.getInstance(XSUAA, DEFAULT_CLIENT_ID)
				.withPrivateKey(keys.getPrivate())
				.withHeaderParameter(TokenHeader.JWKS_URL, "http://auth.com/token_keys")
				.createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void createToken_discoverOidcJwksEndpoint_tokenIsValid() throws Exception {
		String clientId = "T000310";
		String url = "https://app.auth.com";
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(IAS)
				.withUrl(url)
				.withClientId(clientId)
				.build();

		OAuth2TokenKeyService tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(any()))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8));
		OAuth2ServiceEndpointsProvider endpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProviderMock.getJwksUri()).thenReturn(URI.create("http://auth.com/token_keys"));
		OidcConfigurationService oidcConfigServiceMock = Mockito.mock(OidcConfigurationService.class);
		when(oidcConfigServiceMock.retrieveEndpoints(any())).thenReturn(endpointsProviderMock);

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration)
				.withOAuth2TokenKeyService(tokenKeyServiceMock)
				.withOidcConfigurationService(oidcConfigServiceMock)
				.build();

		Token token = JwtGenerator.getInstance(Service.IAS, clientId)
				.withClaimValue(TokenClaims.ISSUER, url)
				.withPrivateKey(keys.getPrivate())
				.withExpiration(JwtGenerator.NO_EXPIRE_DATE)
				.createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}
}
