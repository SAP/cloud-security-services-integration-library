package com.sap.cloud.security.javasec.test;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.validators.JwtSignatureValidator;
import com.sap.cloud.security.xsuaa.client.TokenKeyServiceWithCache;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static com.sap.cloud.security.javasec.test.JwtGenerator.SignatureCalculator;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class JwtGeneratorTest {

	private JwtGenerator cut;
	private RSAKeys keys;

	@Before
	public void setUp() {
		keys = RSAKeys.generate();
		cut = new JwtGenerator().withPrivateKey(keys.getPrivate());
	}

	@Test
	public void createToken_isNotNull()  {
		Token token = cut.createToken();

		assertThat(token).isNotNull();
	}

	@Test
	public void createToken_withoutPrivateKey_throwsException()  {
		assertThatThrownBy(() -> new JwtGenerator().createToken())
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void withClaim_containsClaim()  {
		String claimName = "claim-name";
		String claimValue = "claim-value";

		Token token = cut.withClaim(claimName, claimValue).createToken();

		assertThat(token.getClaimAsString(claimName)).isEqualTo(claimValue);
	}

	@Test
	public void withPrivateKey_usesPrivateKey()  {

		SignatureCalculator signatureCalculatorMock = Mockito.mock(SignatureCalculator.class);
		when(signatureCalculatorMock.calculateSignature(any(), any(), any())).thenReturn("sig".getBytes());

		new JwtGenerator(signatureCalculatorMock).withPrivateKey(keys.getPrivate()).createToken();

		verify(signatureCalculatorMock, times(1)).calculateSignature(eq(keys.getPrivate()), any(), any());
	}

	@Test
	public void withHeaderParameter_containsHeaderParameter()  {
		String parameterName = "the-key";
		String parameterValue = "the-value";

		Token token = cut.withHeaderParameter(parameterName, parameterValue).createToken();

		assertThat(token.getHeaderParameterAsString(parameterName)).isEqualTo(parameterValue);
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

}
