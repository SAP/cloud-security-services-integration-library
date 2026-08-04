/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.when;

/**
 * End-to-end test of the IAS signature validation path for every algorithm declared in
 * {@link JwtSignatureAlgorithm}. Each iteration:
 * <ol>
 *   <li>generates a fresh key pair for the algorithm,
 *   <li>builds a synthetic JWKS JSON containing the matching public key,
 *   <li>signs a token whose claims satisfy {@link SapIdJwtSignatureValidator}'s issuer / app_tid rules,
 *   <li>routes the token through the real validator with mocked transport.
 * </ol>
 * Complements {@link JwtSignatureAlgorithmTest}, which exercises {@code validateSignature} in
 * isolation: this test additionally drives the JWKS parser and key construction path that
 * {@link SapIdJwtSignatureValidator#getPublicKey} relies on.
 */
class SapIdJwtSignatureValidatorAlgorithmsTest {

	private static final String ISSUER = "https://test.example.com";
	private static final String CLIENT_ID = "client-id";
	private static final String KEY_ID = "test-kid";
	private static final URI JWKS_URI = URI.create("https://test.example.com/jwks_uri");

	private OAuth2TokenKeyService tokenKeyServiceMock;
	private SapIdJwtSignatureValidator cut;

	@BeforeEach
	void setup() throws OAuth2ServiceException {
		OAuth2ServiceConfiguration mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.getService()).thenReturn(Service.IAS);
		when(mockConfiguration.getClientId()).thenReturn(CLIENT_ID);
		when(mockConfiguration.getUrl()).thenReturn(URI.create(ISSUER));

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);

		OAuth2ServiceEndpointsProvider endpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProviderMock.getJwksUri()).thenReturn(JWKS_URI);

		OidcConfigurationService oidcConfigServiceMock = Mockito.mock(OidcConfigurationService.class);
		when(oidcConfigServiceMock.retrieveEndpoints(any())).thenReturn(endpointsProviderMock);

		cut = new SapIdJwtSignatureValidator(
				mockConfiguration,
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(oidcConfigServiceMock));
	}

	@AfterEach
	void tearDown() {
		// Singleton caches outlive the test instance; clear both so the next iteration cannot
		// pick up the previous algorithm's key set from the cache.
		OAuth2TokenKeyServiceWithCache.getInstance().clearCache();
		OidcConfigurationServiceWithCache.getInstance().clearCache();
	}

	@ParameterizedTest
	@EnumSource(JwtSignatureAlgorithm.class)
	void validate_acceptsTokenForEveryAlgorithm(JwtSignatureAlgorithm algorithm) throws Exception {
		KeyPair keyPair = generateKeyPair(algorithm);
		String jwks = buildJwks(algorithm, keyPair);
		when(tokenKeyServiceMock.retrieveTokenKeys(any(), anyMap())).thenReturn(jwks);

		String tokenValue = createSignedToken(algorithm, keyPair);
		Token token = new SapIdToken(tokenValue);

		ValidationResult result = cut.validate(token);

		assertThat(result.isValid())
				.as("end-to-end validation should accept a freshly signed %s token: %s",
						algorithm.value(), result.getErrorDescription())
				.isTrue();
	}

	@ParameterizedTest
	@EnumSource(JwtSignatureAlgorithm.class)
	void validate_rejectsTamperedTokenForEveryAlgorithm(JwtSignatureAlgorithm algorithm) throws Exception {
		KeyPair keyPair = generateKeyPair(algorithm);
		when(tokenKeyServiceMock.retrieveTokenKeys(any(), anyMap())).thenReturn(buildJwks(algorithm, keyPair));

		String tokenValue = createSignedToken(algorithm, keyPair);
		String[] parts = tokenValue.split("\\.");
		// Flip the FIRST char of the signature, not the last. Base64url without padding can have
		// up-to-four bits at the tail that don't map to a decoded byte — flipping the last char
		// may leave the decoded signature bytes unchanged for signatures whose length isn't a
		// multiple of three. The first char always contributes six real bits, so this is safe.
		char first = parts[2].charAt(0);
		String tamperedSig = (first == 'A' ? 'B' : 'A') + parts[2].substring(1);
		Token tampered = new SapIdToken(parts[0] + "." + parts[1] + "." + tamperedSig);

		assertThat(cut.validate(tampered).isErroneous())
				.as("tampered %s token must be rejected", algorithm.value())
				.isTrue();
	}

	private static KeyPair generateKeyPair(JwtSignatureAlgorithm algorithm) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.type());
		if ("EC".equals(algorithm.type())) {
			generator.initialize(new ECGenParameterSpec(nistCurveName(algorithm.curveName())));
		} else {
			generator.initialize(2048);
		}
		return generator.generateKeyPair();
	}

	private static String buildJwks(JwtSignatureAlgorithm algorithm, KeyPair keyPair) {
		if ("EC".equals(algorithm.type())) {
			ECPublicKey ecKey = (ECPublicKey) keyPair.getPublic();
			int len = algorithm.coordinateLength();
			String x = base64Url(toUnsignedFixedLength(ecKey.getW().getAffineX().toByteArray(), len));
			String y = base64Url(toUnsignedFixedLength(ecKey.getW().getAffineY().toByteArray(), len));
			return "{\"keys\":[{"
					+ "\"kty\":\"EC\","
					+ "\"kid\":\"" + KEY_ID + "\","
					+ "\"alg\":\"" + algorithm.value() + "\","
					+ "\"crv\":\"" + algorithm.curveName() + "\","
					+ "\"x\":\"" + x + "\","
					+ "\"y\":\"" + y + "\"}]}";
		}
		RSAPublicKey rsaKey = (RSAPublicKey) keyPair.getPublic();
		String n = base64Url(stripLeadingZero(rsaKey.getModulus().toByteArray()));
		String e = base64Url(stripLeadingZero(rsaKey.getPublicExponent().toByteArray()));
		return "{\"keys\":[{"
				+ "\"kty\":\"RSA\","
				+ "\"kid\":\"" + KEY_ID + "\","
				+ "\"alg\":\"" + algorithm.value() + "\","
				+ "\"n\":\"" + n + "\","
				+ "\"e\":\"" + e + "\"}]}";
	}

	private static String createSignedToken(JwtSignatureAlgorithm algorithm, KeyPair keyPair) throws Exception {
		String header = base64Url(("{\"alg\":\"" + algorithm.value() + "\",\"kid\":\"" + KEY_ID + "\",\"typ\":\"JWT\"}")
				.getBytes(StandardCharsets.UTF_8));
		// Issuer matches the configured URL → SapIdJwtSignatureValidator does not require app_tid.
		String payload = base64Url(("{\"iss\":\"" + ISSUER + "\","
				+ "\"sub\":\"test-user\","
				+ "\"aud\":\"" + CLIENT_ID + "\","
				+ "\"cid\":\"" + CLIENT_ID + "\","
				+ "\"exp\":6974031600}").getBytes(StandardCharsets.UTF_8));
		String signingInput = header + "." + payload;

		Signature signature = Signature.getInstance(algorithm.javaSignature());
		AlgorithmParameterSpec parameterSpec = algorithm.parameterSpec();
		if (parameterSpec != null) {
			signature.setParameter(parameterSpec);
		}
		signature.initSign(keyPair.getPrivate());
		signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
		return signingInput + "." + base64Url(signature.sign());
	}

	private static String nistCurveName(String jwkCurveName) {
		switch (jwkCurveName) {
			case "P-256": return "secp256r1";
			case "P-384": return "secp384r1";
			case "P-521": return "secp521r1";
			default: throw new IllegalArgumentException("Unknown JWK curve: " + jwkCurveName);
		}
	}

	/**
	 * BigInteger#toByteArray returns a two's-complement representation that may include a leading
	 * 0x00 sign byte for positive values whose top bit is set. JWK n/e are unsigned big-endian
	 * (RFC 7518), so the leading zero has to go.
	 */
	private static byte[] stripLeadingZero(byte[] bytes) {
		if (bytes.length > 1 && bytes[0] == 0) {
			byte[] out = new byte[bytes.length - 1];
			System.arraycopy(bytes, 1, out, 0, out.length);
			return out;
		}
		return bytes;
	}

	/**
	 * Coerces a BigInteger's two's-complement bytes to a fixed-length unsigned big-endian octet
	 * string, as RFC 7518 §6.2.1.2/§6.2.1.3 requires for the EC x and y coordinates.
	 */
	private static byte[] toUnsignedFixedLength(byte[] bytes, int length) {
		byte[] unsigned = stripLeadingZero(bytes);
		if (unsigned.length == length) {
			return unsigned;
		}
		if (unsigned.length > length) {
			throw new IllegalStateException("coordinate longer than expected: " + unsigned.length + " > " + length);
		}
		byte[] padded = new byte[length];
		System.arraycopy(unsigned, 0, padded, length - unsigned.length, unsigned.length);
		return padded;
	}

	private static String base64Url(byte[] bytes) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}
}