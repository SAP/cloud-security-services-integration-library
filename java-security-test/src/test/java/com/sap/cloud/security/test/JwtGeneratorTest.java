package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.token.validation.validators.JwtSignatureValidator;
import com.sap.cloud.security.xsuaa.client.TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.jwt.JwtSignatureAlgorithm;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.test.JwtGenerator.SignatureCalculator;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.util.Lists.list;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class JwtGeneratorTest {

	private JwtGenerator cut;
	private RSAKeys keys;

	@Before
	public void setUp() {
		keys = RSAKeys.generate();
		cut = JwtGenerator.getInstance(XSUAA).withPrivateKey(keys.getPrivate());
	}

	@Test
	public void createToken_isNotNull() {
		Token token = cut.createToken();

		assertThat(token).isNotNull();
	}

	@Test
	public void createToken_withoutPrivateKey_throwsException() {
		assertThatThrownBy(() -> JwtGenerator.getInstance(IAS).createToken())
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void withClaim_containsClaim() {
		String claimName = "claim-name";
		String claimValue = "claim-value";

		Token token = cut.withClaim(claimName, claimValue).createToken();

		assertThat(token.getClaimAsString(claimName)).isEqualTo(claimValue);
	}

	@Test
	public void withPrivateKey_usesPrivateKey() throws Exception {
		SignatureCalculator signatureCalculator = Mockito.mock(SignatureCalculator.class);

		when(signatureCalculator.calculateSignature(any(), any(), any())).thenReturn("sig".getBytes());

		JwtGenerator.getInstance(IAS, signatureCalculator).withPrivateKey(keys.getPrivate()).createToken();

		verify(signatureCalculator, times(1)).calculateSignature(eq(keys.getPrivate()), any(), any());
	}

	@Test
	public void withHeaderParameter_containsHeaderParameter() {
		String parameterName = "the-key";
		String parameterValue = "the-value";

		Token token = cut.withHeaderParameter(parameterName, parameterValue).createToken();

		assertThat(token.getHeaderParameterAsString(parameterName)).isEqualTo(parameterValue);
	}

	@Test
	public void withJku_containsJkuHeaderParameter() {
		String tokenKeyService = "http://localhost/token_keys";
		Token token = cut.withJku(tokenKeyService).createToken();

		assertThat(token.getHeaderParameterAsString(TokenHeader.JWKS_URL)).isEqualTo(tokenKeyService);
	}

	@Test
	public void withKid_containsKeyIdHeaderParameter() {
		String keyId = "theKeyId";
		Token token = cut.withKeyId(keyId).createToken();

		assertThat(token.getHeaderParameterAsString(TokenHeader.KEY_ID)).isEqualTo(keyId);
	}

	@Test
	public void withScopes_containsScopeWhenServiceIsXsuaa() {
		String firstScope = "firstScope";
		String secondScope = "secondScope";
		Token token = cut.withScopes(firstScope, secondScope).createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)).containsExactly(firstScope, secondScope);
	}

	@Test
	public void withScopes_throwsIllegalStateExceptionWhenServiceIsNotXsuaa() {
		cut = JwtGenerator.getInstance(IAS).withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.withScopes("firstScope").createToken())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContainingAll("Scopes", "XSUAA");
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
	public void withClaim_createsTokenWithValuesAsStringList() {
		String claimName = "claimName";
		String firstValue = "many";
		String secondValue = "values";

		Token token = cut.withClaim(claimName, list(firstValue, secondValue)).createToken();

		assertThat(token.getClaimAsStringList(claimName)).containsExactly(firstValue, secondValue);
	}

	@Test
	public void withSignatureAlgorithm_privateKeyDoesNotMatch_throwsRuntimeException() {
		assertThatThrownBy(() -> cut.withSignatureAlgorithm(JwtSignatureAlgorithm.ES256).createToken())
				.isInstanceOf(RuntimeException.class);
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

}
