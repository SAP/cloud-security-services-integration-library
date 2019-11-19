package com.sap.cloud.security.javasec.test;

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

	private static final String RS256 = "RS256";
	private static final String HS256 = "HS256";
	private static final String RSA = "RSA";

	private final PublicKey publicKey;
	private final PrivateKey privateKey;
	private JwtGenerator cut;

	public JwtGeneratorTest() throws NoSuchAlgorithmException {
		KeyPair keys = KeyPairGenerator.getInstance(RSA).generateKeyPair();
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
		Token token = cut.withAlgorithm(HS256).createToken();

		assertThat(token.getHeaderParameterAsString(ALGORITHM_PARAMETER_NAME)).isEqualTo("HS256");
	}

	@Test
	public void withClaim_containsClaim() throws Exception {
		String claimName = "claim-name";
		String claimValue = "claim-value";

		Token token = cut.withClaim(claimName, claimValue).createToken();

		assertThat(token.getClaimAsString(claimName)).isEqualTo(claimValue);
	}

	@Test
	public void withHeaderParameter_containsHeaderParameter() throws Exception {
		String parmeterName = "the-key";
		String parameterValue = "the-value";

		Token token = cut.withHeaderParameter(parmeterName, parameterValue).createToken();

		assertThat(token.getHeaderParameterAsString(parmeterName)).isEqualTo(parameterValue);
	}

	@Test
	public void withAlgorithm_createsTokenWithCorrectSignature() throws Exception {
		Token token = cut
				.withAlgorithm(RS256)
				.withHeaderParameter("test-123", "321abc")
				.withClaim("test-claim-123", "qwerty")
				.createToken();

		TokenKeyServiceWithCache tokenKeyServiceMock = Mockito.mock(TokenKeyServiceWithCache.class);
		when(tokenKeyServiceMock.getPublicKey(any(), any(), any())).thenReturn(publicKey);

		JwtSignatureValidator validator = new JwtSignatureValidator(tokenKeyServiceMock);
		assertThat(validator.validate(token).isValid()).isTrue();
	}

}
