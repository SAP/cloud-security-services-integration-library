package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.CombiningValidator;
import com.sap.cloud.security.token.validation.validators.JwtSignatureValidator;
import com.sap.cloud.security.token.validation.validators.TokenValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;
import com.sap.cloud.security.xsuaa.jwt.JwtSignatureAlgorithm;
import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Properties;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.test.JwtGenerator.SignatureCalculator;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class JwtGeneratorTest {

	private JwtGenerator cut;
	private static RSAKeys keys;
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
		cut = JwtGenerator.getInstance(XSUAA).withPrivateKey(keys.getPrivate());
	}

	@After
	public void tearDown() {
		System.setProperties(originalSystemProperties);
	}

	@Test
	public void createToken_isNotNull() {
		Token token = cut.createToken();

		assertThat(token).isNotNull();
		assertThat(token.containsClaim(TokenClaims.AUDIENCE)).isFalse();
	}

	@Test
	public void createToken_withoutPrivateKey_throwsException() {
		assertThatThrownBy(() -> JwtGenerator.getInstance(IAS).createToken())
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void withPrivateKey_usesPrivateKey() throws Exception {
		SignatureCalculator signatureCalculator = Mockito.mock(SignatureCalculator.class);

		when(signatureCalculator.calculateSignature(any(), any(), any())).thenReturn("sig".getBytes());

		JwtGenerator.getInstance(IAS, signatureCalculator).withPrivateKey(keys.getPrivate()).createToken();

		verify(signatureCalculator, times(1)).calculateSignature(eq(keys.getPrivate()), any(), any());
	}

	@Test
	public void withClaim_containsClaim() {
		String clientId = "myClientId";
		String subdomain = "subdomain";

		Token token = cut
				.withClaimValue(TokenClaims.XSUAA.SUBDOMAIN, subdomain)
				.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, clientId)
				.createToken();

		assertThat(token.getClaimAsString(TokenClaims.XSUAA.SUBDOMAIN)).isEqualTo(subdomain);
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
		cut = JwtGenerator.getInstance(IAS).withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.withScopes("firstScope").createToken())
				.isInstanceOf(UnsupportedOperationException.class)
				.hasMessageContainingAll("Scopes", "IAS");
	}

	@Test
	public void withAlgorithm_createsTokenWithSignature_isValid() throws Exception {
		RSAKeys keys = RSAKeys.generate();

		Token token = cut.withPrivateKey(keys.getPrivate()).createToken();

		TokenKeyServiceWithCache tokenKeyServiceMock = Mockito.mock(TokenKeyServiceWithCache.class);
		when(tokenKeyServiceMock.getPublicKey(any(), any(), any())).thenReturn(keys.getPublic());

		JwtSignatureValidator validator = new JwtSignatureValidator(tokenKeyServiceMock);
		assertThat(validator.validate(token).isValid()).isTrue();
	}

	@Test
	public void withClaim_createsTokenWithAudience() {
		String[] audiences = { "app1", "app2" };

		Token token = cut.withClaimValues(TokenClaims.AUDIENCE, audiences).createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.AUDIENCE)).containsExactly(audiences);
	}

	@Test
	public void deriveAudience_createsTokenWithDerivedAudiences() {
		String[] scopes = { "openid", "app1.scope", "app2.sub.scope", "app2.scope", ".scopeWithoutAppId" };

		Token token = cut.withScopes(scopes).deriveAudience(true).createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.AUDIENCE)).containsExactlyInAnyOrder("app1", "app2");
	}

	@Test
	public void createsTokenWithDerivedAudiencesAndCustomAudiences() {
		String[] scopes = { "openid", "app1.scope", "app2.sub.scope", "app2.scope", ".scopeWithoutAppId" };

		Token token = cut.withScopes(scopes)
				.withClaimValues(TokenClaims.AUDIENCE, "app3")
				.deriveAudience(true)
				.createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.AUDIENCE)).containsExactlyInAnyOrder("app1", "app2", "app3");
	}

	@Test
	public void withSignatureAlgorithm_notSupported_throwsUnsupportedOperationException() {
		assertThatThrownBy(() -> cut.withSignatureAlgorithm(JwtSignatureAlgorithm.ES256))
				.isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	public void createToken_signatureCalculation_NoSuchAlgorithmExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new NoSuchAlgorithmException();
		}).withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_signatureCalculation_SignatureExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new SignatureException();
		}).withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_signatureCalculation_InvalidKeyExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new InvalidKeyException();
		}).withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_tokenIsValid() throws IOException {
		System.setProperty("VCAP_SERVICES", IOUtils
				.resourceToString("/vcap.json", StandardCharsets.UTF_8));
		OAuth2ServiceConfiguration configuration = Environments.getCurrentEnvironment().getXsuaaServiceConfiguration();

		OAuth2TokenKeyService tokenKeyService = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyService.retrieveTokenKeys(any())).thenReturn(JsonWebKeySetFactory.createFromJson(
				IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8)));

		CombiningValidator<Token> tokenValidator = TokenValidatorBuilder.createFor(configuration)
				.withOAuth2TokenKeyService(tokenKeyService)
				.build();

		Token token = cut
				.withHeaderParameter(TokenHeader.JWKS_URL, "http://auth.com/token_keys")
				.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, "xs2.usertoken")
				.createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}


}
