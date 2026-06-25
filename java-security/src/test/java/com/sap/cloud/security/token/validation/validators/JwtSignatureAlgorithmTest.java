/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that {@link JwtSignatureValidator#validateSignature(Token, PublicKey, JwtSignatureAlgorithm)}
 * accepts every algorithm declared in {@link JwtSignatureAlgorithm}. The test builds a real JWT-shaped
 * input (header.payload.signature), signs it with a freshly generated key pair using the JCA algorithm
 * the enum advertises, and feeds the result through {@code validateSignature}.
 */
class JwtSignatureAlgorithmTest {

	@Test
	void enum_values_areTheExpectedSet() {
		assertThat(JwtSignatureAlgorithm.values())
				.extracting(JwtSignatureAlgorithm::value)
				.containsExactly("RS256", "RS384", "RS512", "PS256", "PS384", "PS512");
	}

	@Test
	void fromValue_unknown_returnsNull() {
		assertThat(JwtSignatureAlgorithm.fromValue("HS256")).isNull();
	}

	@Test
	void fromType_rsa_returnsRs256() {
		assertThat(JwtSignatureAlgorithm.fromType("RSA")).isEqualTo(JwtSignatureAlgorithm.RS256);
	}

	@Test
	void fromType_unknown_returnsNull() {
		assertThat(JwtSignatureAlgorithm.fromType("EC")).isNull();
		assertThat(JwtSignatureAlgorithm.fromType("oct")).isNull();
	}

	@ParameterizedTest
	@EnumSource(JwtSignatureAlgorithm.class)
	void validateSignature_acceptsTokenSignedWithAlgorithm(JwtSignatureAlgorithm algorithm) throws Exception {
		KeyPair keyPair = generateKeyPair(algorithm);
		String signedToken = createSignedToken(algorithm, keyPair);

		Token token = Mockito.mock(Token.class);
		Mockito.when(token.getTokenValue()).thenReturn(signedToken);

		ValidationResult result = new TestValidator(keyPair.getPublic())
				.validateSignature(token, keyPair.getPublic(), algorithm);

		assertThat(result.isValid())
				.as("validation should accept a token signed with %s", algorithm.value())
				.isTrue();
	}

	@ParameterizedTest
	@EnumSource(JwtSignatureAlgorithm.class)
	void validateSignature_rejectsTamperedToken(JwtSignatureAlgorithm algorithm) throws Exception {
		KeyPair keyPair = generateKeyPair(algorithm);
		String signedToken = createSignedToken(algorithm, keyPair);
		// Flip a byte in the payload section to invalidate the signature
		String[] parts = signedToken.split("\\.");
		String tamperedPayload = parts[1].substring(0, parts[1].length() - 1)
				+ (parts[1].charAt(parts[1].length() - 1) == 'A' ? 'B' : 'A');
		String tampered = parts[0] + "." + tamperedPayload + "." + parts[2];

		Token token = Mockito.mock(Token.class);
		Mockito.when(token.getTokenValue()).thenReturn(tampered);

		ValidationResult result = new TestValidator(keyPair.getPublic())
				.validateSignature(token, keyPair.getPublic(), algorithm);

		assertThat(result.isValid())
				.as("tampered token must be rejected for %s", algorithm.value())
				.isFalse();
	}

	private static KeyPair generateKeyPair(JwtSignatureAlgorithm algorithm) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.type());
		generator.initialize(2048);
		return generator.generateKeyPair();
	}

	private static String createSignedToken(JwtSignatureAlgorithm algorithm, KeyPair keyPair) throws Exception {
		String header = base64Url(("{\"alg\":\"" + algorithm.value() + "\",\"typ\":\"JWT\"}")
				.getBytes(StandardCharsets.UTF_8));
		String payload = base64Url("{\"sub\":\"test\"}".getBytes(StandardCharsets.UTF_8));
		String signingInput = header + "." + payload;

		Signature signature = Signature.getInstance(algorithm.javaSignature());
		AlgorithmParameterSpec parameterSpec = algorithm.parameterSpec();
		if (parameterSpec != null) {
			signature.setParameter(parameterSpec);
		}
		signature.initSign(keyPair.getPrivate());
		signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
		byte[] signatureBytes = signature.sign();

		return signingInput + "." + base64Url(signatureBytes);
	}

	private static String base64Url(byte[] bytes) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	/**
	 * Concrete {@link JwtSignatureValidator} subclass that bypasses the JWKS lookup so we can
	 * exercise {@code validateSignature} in isolation.
	 */
	private static final class TestValidator extends JwtSignatureValidator {
		private final PublicKey publicKey;

		TestValidator(PublicKey publicKey) {
			super(Mockito.mock(OAuth2ServiceConfiguration.class),
					Mockito.mock(OAuth2TokenKeyServiceWithCache.class),
					Mockito.mock(OidcConfigurationServiceWithCache.class));
			this.publicKey = publicKey;
		}

		@Override
		protected PublicKey getPublicKey(Token token, JwtSignatureAlgorithm algorithm) throws OAuth2ServiceException {
			return publicKey;
		}
	}
}