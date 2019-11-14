package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.validators.JwtSignatureValidator;
import com.sap.cloud.security.xsuaa.client.TokenKeyServiceWithCache;
import org.junit.Test;
import org.mockito.Mockito;

import java.security.*;

import static com.sap.cloud.security.xsuaa.jwk.JsonWebKeyConstants.ALGORITHM_PARAMETER_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class JwtGeneratorTest {

	private final PublicKey publicKey;
	private final PrivateKey privateKey;
	private JwtGenerator cut;

	public JwtGeneratorTest() throws NoSuchAlgorithmException {
		KeyPair keys = KeyPairGenerator.getInstance(JwtConstants.RSA).generateKeyPair();
		privateKey = keys.getPrivate();
		publicKey = keys.getPublic();
		cut = new JwtGenerator(privateKey);
	}

	@Test
	public void createToken_isNotNull() throws Exception {
		Token token = cut.createToken();

		assertThat(token).isNotNull();
	}

	@Test
	public void withAlgorithm_containsAlgorithm() throws Exception {
		Token token = cut.withAlgorithm("HS256").createToken();

		assertThat(token.getHeaderParameterAsString(ALGORITHM_PARAMETER_NAME)).isEqualTo(JwtConstants.Algorithms.HS256);
	}

	@Test
	public void withAlgorithm_createsTokenWithCorrectSignature() throws Exception {
		Token token = cut
				.withAlgorithm(JwtConstants.Algorithms.RS256)
				.createToken();

		TokenKeyServiceWithCache tokenKeyServiceMock = Mockito.mock(TokenKeyServiceWithCache.class);
		when(tokenKeyServiceMock.getPublicKey(any(), any(), any())).thenReturn(publicKey);

		JwtSignatureValidator validator = new JwtSignatureValidator(tokenKeyServiceMock);
		assertThat(validator.validate(token).isValid()).isTrue();
	}

}
