package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.validators.JwtSignatureValidator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.*;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;
import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;
import sun.security.rsa.RSAPublicKeyImpl;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Properties;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.test.JwtGenerator.SignatureCalculator;
import static com.sap.cloud.security.test.SecurityTestRule.DEFAULT_CLIENT_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class JwtGeneratorTest {

	private static RSAKeys keys;
	private JwtGenerator cut;
	private Properties originalSystemProperties;

	@BeforeClass
	public static void setUpClass() throws Exception {
		String publicKeyPath = IOUtils.resourceToURL("/publicKey.txt").getPath();
		String privateKeyPath = IOUtils.resourceToURL("/privateKey.txt").getPath();
		keys = RSAKeys.fromKeyFiles(publicKeyPath, privateKeyPath);
	}

	@Before
	public void setUp() {
		originalSystemProperties = System.getProperties();
		cut = JwtGenerator.getInstance(XSUAA, DEFAULT_CLIENT_ID).withPrivateKey(keys.getPrivate());
	}

	@After
	public void tearDown() {
		System.setProperties(originalSystemProperties);
	}

	@Test
	public void createToken_isNotNull() {
		Token token = cut.createToken();

		assertThat(token).isNotNull();
		assertThat(token.getClaimAsStringList(TokenClaims.AUDIENCE)).contains(DEFAULT_CLIENT_ID);
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo(DEFAULT_CLIENT_ID);
		assertThat(token.getExpiration()).isEqualTo(JwtGenerator.NO_EXPIRE_DATE);
	}

	@Test
	public void createIasToken_isNotNull() {
		cut = JwtGenerator.getInstance(IAS, "T000310")
				.withClaimValue("sub", "P176945")
				.withClaimValue("scope", "john.doe")
				.withClaimValue("iss", "https://application.auth.com")
				.withClaimValue("first_name", "john")
				.withClaimValue("last_name", "doe")
				.withClaimValue("email", "john.doe@email.org")
				.withPrivateKey(keys.getPrivate());
		Token token = cut.createToken();

		assertThat(token).isNotNull();
		assertThat(token.getClaimAsString(TokenClaims.AUDIENCE)).isEqualTo("T000310");
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo("T000310");
		assertThat(token.getExpiration()).isEqualTo(JwtGenerator.NO_EXPIRE_DATE);
		String encodedModulusN = Base64.getUrlEncoder()
				.encodeToString(((RSAPublicKeyImpl) keys.getPublic()).getModulus().toByteArray());
		assertThat(encodedModulusN).startsWith("AJtUGmczI7RHx3");
	}

	@Test
	public void createToken_withoutPrivateKey_throwsException() {
		assertThatThrownBy(() -> JwtGenerator.getInstance(IAS, "T00001234").createToken())
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void withPrivateKey_usesPrivateKey() throws Exception {
		SignatureCalculator signatureCalculator = Mockito.mock(SignatureCalculator.class);

		when(signatureCalculator.calculateSignature(any(), any(), any())).thenReturn("sig".getBytes());

		JwtGenerator.getInstance(IAS, signatureCalculator, "T00001234").withPrivateKey(keys.getPrivate()).createToken();

		verify(signatureCalculator, times(1)).calculateSignature(eq(keys.getPrivate()), any(), any());
	}

	@Test
	public void withClaim_containsClaim() {
		String email = "john.doe@mail.de";

		Token token = cut
				.withClaimValue(TokenClaims.XSUAA.EMAIL, email)
				.createToken();

		assertThat(token.getClaimAsString(TokenClaims.XSUAA.EMAIL)).isEqualTo(email);
	}

	@Test
	public void withClaimClientId_overwritesClaim() {
		String clientId = "myClientId";

		Token token = cut
				.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, clientId)
				.createToken();

		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo(clientId);
	}

	@Test
	public void withHeaderParameter_containsHeaderParameter() {
		String tokenKeyServiceUrl = "http://localhost/token_keys";
		String keyId = "theKeyId";
		Token token = cut.withHeaderParameter(TokenHeader.JWKS_URL, tokenKeyServiceUrl)
				.withHeaderParameter(TokenHeader.KEY_ID, keyId)
				.createToken();

		assertThat(token.getHeaderParameterAsString(TokenHeader.KEY_ID)).isEqualTo(keyId);
		assertThat(token.getHeaderParameterAsString(TokenHeader.JWKS_URL)).isEqualTo(tokenKeyServiceUrl);
	}

	@Test
	public void withScopes_containsScopeWhenServiceIsXsuaa() {
		String[] scopes = new String[] { "openid", "app1.scope" };
		Token token = cut.withScopes(scopes).createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)).containsExactly(scopes);
	}

	@Test
	public void withScopes_serviceIsIAS_throwsUnsupportedOperationException() {
		cut = JwtGenerator.getInstance(IAS, "T00001234").withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.withScopes("firstScope").createToken())
				.isInstanceOf(UnsupportedOperationException.class)
				.hasMessage("Scopes are not supported for service IAS");
	}

	@Test
	public void withExpiration_createsTokenWithExpiration() {
		Instant expiration = LocalDate.of(2019, 1, 1).atStartOfDay().toInstant(ZoneOffset.UTC);

		Token token = cut.withExpiration(expiration).createToken();

		assertThat(token.getExpiration()).isEqualTo(expiration);
	}

	@Test
	public void withSignatureAlgorithm_notSupported_throwsUnsupportedOperationException() {
		assertThatThrownBy(() -> cut.withClaimValues(TokenClaims.AUDIENCE, "app2", "app3"))
				.isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	public void createToken_signatureCalculation_NoSuchAlgorithmExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new NoSuchAlgorithmException();
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_signatureCalculation_SignatureExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new SignatureException();
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_signatureCalculation_InvalidKeyExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new InvalidKeyException();
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_tokenIsValid() throws IOException {
		System.setProperty("VCAP_SERVICES", IOUtils
				.resourceToString("/vcap.json", StandardCharsets.UTF_8));
		OAuth2ServiceConfiguration configuration = Environments.getCurrent().getXsuaaConfiguration();

		OAuth2TokenKeyService tokenKeyService = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyService.retrieveTokenKeys(any())).thenReturn(JsonWebKeySetFactory.createFromJson(
				IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8)));

		OAuth2TokenKeyServiceWithCache oAuth2TokenKeyServiceWithCache = OAuth2TokenKeyServiceWithCache.getInstance();
		oAuth2TokenKeyServiceWithCache.withTokenKeyService(tokenKeyService);
		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration)
				.withOAuth2TokenKeyService(oAuth2TokenKeyServiceWithCache)
				.build();

		Token token = cut
				.withHeaderParameter(TokenHeader.JWKS_URL, "http://auth.com/token_keys")
				.withExpiration(JwtGenerator.NO_EXPIRE_DATE)
				.createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void createToken_discoverOidcJwksEndpoint_tokenIsValid() throws Exception {
		RSAKeys keys = RSAKeys.generate();

		Token token = cut
				.withClaimValue(TokenClaims.ISSUER, "http://auth.com")
				.withPrivateKey(keys.getPrivate()).createToken();

		OAuth2TokenKeyServiceWithCache tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyServiceWithCache.class);
		when(tokenKeyServiceMock.getPublicKey(any(), any(), any())).thenReturn(keys.getPublic());

		OAuth2ServiceEndpointsProvider endpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProviderMock.getJwksUri()).thenReturn(URI.create("http://auth.com/token_keys"));

		OidcConfigurationService oidcConfigServiceMock = Mockito.mock(OidcConfigurationService.class);
		when(oidcConfigServiceMock.retrieveEndpoints(any())).thenReturn(endpointsProviderMock);
		OidcConfigurationServiceWithCache oidcConfigurationService = OidcConfigurationServiceWithCache
				.getInstance().withOidcConfigurationService(oidcConfigServiceMock);

		JwtSignatureValidator validator = new JwtSignatureValidator(tokenKeyServiceMock, oidcConfigurationService);

		assertThat(validator.validate(token).isValid()).isTrue();
	}

}
