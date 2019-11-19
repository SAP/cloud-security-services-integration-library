package com.sap.cloud.security.javasec.test;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.validators.JwtSignatureValidator;
import com.sap.cloud.security.xsuaa.client.TokenKeyServiceWithCache;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class JwtGeneratorTest {

	private final RSAKeypair rsaKeypair;
	private JwtGenerator cut;

	public JwtGeneratorTest() {
		rsaKeypair = new RSAKeypair();
	}

	@Before
	public void setUp() {
		cut = new JwtGenerator();
	}

	@Test
	public void createToken_isNotNull() throws Exception {
		Token token = cut.createToken(rsaKeypair.getPrivate());

		assertThat(token).isNotNull();
	}

	@Test
	public void withClaim_containsClaim() throws Exception {
		String claimName = "claim-name";
		String claimValue = "claim-value";

		Token token = cut.withClaim(claimName, claimValue).createToken(rsaKeypair.getPrivate());

		assertThat(token.getClaimAsString(claimName)).isEqualTo(claimValue);
	}

	@Test
	public void withHeaderParameter_containsHeaderParameter() throws Exception {
		String parmeterName = "the-key";
		String parameterValue = "the-value";

		Token token = cut.withHeaderParameter(parmeterName, parameterValue).createToken(rsaKeypair.getPrivate());

		assertThat(token.getHeaderParameterAsString(parmeterName)).isEqualTo(parameterValue);
	}

	@Test
	public void withAlgorithm_createsTokenWithSignature_isValid() throws Exception {
		Token token = cut.withHeaderParameter("test-123", "321abc")
				.withClaim("test-claim-123", "qwerty")
				.createToken(rsaKeypair.getPrivate());

		TokenKeyServiceWithCache tokenKeyServiceMock = Mockito.mock(TokenKeyServiceWithCache.class);
		when(tokenKeyServiceMock.getPublicKey(any(), any(), any())).thenReturn(rsaKeypair.getPublic());

		JwtSignatureValidator validator = new JwtSignatureValidator(tokenKeyServiceMock);
		assertThat(validator.validate(token).isValid()).isTrue();
	}

}
