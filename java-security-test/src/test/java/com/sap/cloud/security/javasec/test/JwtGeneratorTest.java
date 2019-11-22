package com.sap.cloud.security.javasec.test;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.validators.JwtSignatureValidator;
import com.sap.cloud.security.xsuaa.client.TokenKeyServiceWithCache;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.security.PublicKey;

import static com.sap.cloud.security.javasec.test.JwtGenerator.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class JwtGeneratorTest {

	private JwtGenerator cut;

	@Before
	public void setUp() {
		cut = new JwtGenerator();
	}

	@Test
	public void createToken_isNotNull()  {
		Token token = cut.createToken();

		assertThat(token).isNotNull();
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
		RSAKeys keys = RSAKeys.generate();

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
	public void withAlgorithm_createsTokenWithSignatureUsingBuiltInKeys_isValid() throws Exception {
		Token token = cut.createToken();

		PublicKey publicKey = RSAKeys.loadPublicKey(IOUtils.resourceToURL("/publicKey.txt").getPath());

		TokenKeyServiceWithCache tokenKeyServiceMock = Mockito.mock(TokenKeyServiceWithCache.class);
		when(tokenKeyServiceMock.getPublicKey(any(), any(), any())).thenReturn(publicKey);

		JwtSignatureValidator validator = new JwtSignatureValidator(tokenKeyServiceMock);
		assertThat(validator.validate(token).isValid()).isTrue();
	}

	@Test
	public void withAlgorithm_createsTokenWithSignatureUsingCustomKeys_isValid() throws Exception {
		RSAKeys keys = RSAKeys.generate();

		Token token = cut.withPrivateKey(keys.getPrivate()).createToken();

		TokenKeyServiceWithCache tokenKeyServiceMock = Mockito.mock(TokenKeyServiceWithCache.class);
		when(tokenKeyServiceMock.getPublicKey(any(), any(), any())).thenReturn(keys.getPublic());

		JwtSignatureValidator validator = new JwtSignatureValidator(tokenKeyServiceMock);
		assertThat(validator.validate(token).isValid()).isTrue();
	}

}
