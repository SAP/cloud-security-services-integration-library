/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import org.junit.jupiter.api.Test;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class JsonWebKeySetFactoryTest {

	private String jsonWebTokenKeys;

	@BeforeEach
	public void setup() throws IOException {
		jsonWebTokenKeys = IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Test
	public void getEmptyJsonWebKeySetWhenJsonIsNull() {
		assertThat(JsonWebKeySetFactory.createFromJson(null).getAll()).isEqualTo(Collections.EMPTY_SET);
	}

	@Test
	public void getKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "key-id-1");
		assertThat(jwk.getKeyAlgorithm().value()).isEqualTo("RS256");
		assertThat(jwk.getKeyAlgorithm().type()).isEqualTo("RSA");
		assertThat(jwk.getPublicKey().getAlgorithm()).isEqualTo(jwk.getKeyAlgorithm().type());
		assertThat(jwk.getId()).isEqualTo("key-id-1");
	}

	@Test
	public void getKeys() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "key-id-1");
		assertThat(jwk.getKeyAlgorithm().value()).isEqualTo("RS256");
		assertThat(jwk.getKeyAlgorithm().type()).isEqualTo("RSA");
		assertThat(jwk.getPublicKey().getAlgorithm()).isEqualTo(jwk.getKeyAlgorithm().type());
		assertThat(jwk.getId()).isEqualTo("key-id-1");
	}

	@Test
	public void getIasKeys() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		jsonWebTokenKeys = IOUtils.resourceToString("/iasJsonWebTokenKeys_noKid.json", StandardCharsets.UTF_8);
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, null);
		assertThat(jwk.getKeyAlgorithm().type()).isEqualTo("RSA");
		assertThat(jwk.getPublicKey().getAlgorithm()).isEqualTo(jwk.getKeyAlgorithm().type());
		assertThat(jwk.getId()).isEqualTo(JsonWebKey.DEFAULT_KEY_ID);
	}

	@Test
	public void parsesPs256Key() throws Exception {
		KeyPair keyPair = generateRsaKey();
		String jwks = buildRsaJwks("PS256", "ps256-kid", keyPair);

		JsonWebKey jwk = JsonWebKeySetFactory.createFromJson(jwks)
				.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.PS256, "ps256-kid");

		assertThat(jwk.getKeyAlgorithm()).isEqualTo(JwtSignatureAlgorithm.PS256);
		assertThat(jwk.getPublicKey().getAlgorithm()).isEqualTo("RSA");
	}

	@Test
	public void parsesEs256Key() throws Exception {
		KeyPair keyPair = generateEcKey("secp256r1");
		String jwks = buildEcJwks("ES256", "P-256", "es256-kid", keyPair, 32);

		JsonWebKey jwk = JsonWebKeySetFactory.createFromJson(jwks)
				.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.ES256, "es256-kid");

		assertThat(jwk.getKeyAlgorithm()).isEqualTo(JwtSignatureAlgorithm.ES256);
		assertThat(jwk.getPublicKey().getAlgorithm()).isEqualTo("EC");
	}

	@Test
	public void parsesEs384Key() throws Exception {
		KeyPair keyPair = generateEcKey("secp384r1");
		String jwks = buildEcJwks("ES384", "P-384", "es384-kid", keyPair, 48);

		JsonWebKey jwk = JsonWebKeySetFactory.createFromJson(jwks)
				.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.ES384, "es384-kid");

		assertThat(jwk.getPublicKey().getAlgorithm()).isEqualTo("EC");
	}

	@Test
	public void parsesEs512Key() throws Exception {
		KeyPair keyPair = generateEcKey("secp521r1");
		String jwks = buildEcJwks("ES512", "P-521", "es512-kid", keyPair, 66);

		JsonWebKey jwk = JsonWebKeySetFactory.createFromJson(jwks)
				.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.ES512, "es512-kid");

		assertThat(jwk.getPublicKey().getAlgorithm()).isEqualTo("EC");
	}

	@Test
	public void ecKey_rejectsMismatchedCurve() throws Exception {
		// Build a JWK that announces alg=ES256 (curve P-256) but provides a P-384 key.
		KeyPair keyPair = generateEcKey("secp384r1");
		String jwks = buildEcJwks("ES256", "P-384", "mismatch-kid", keyPair, 48);

		JsonWebKey jwk = JsonWebKeySetFactory.createFromJson(jwks)
				.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.ES256, "mismatch-kid");

		assertThatThrownBy(jwk::getPublicKey)
				.isInstanceOf(InvalidKeySpecException.class)
				.hasMessageContaining("does not match algorithm ES256");
	}

	@Test
	public void ecKey_rejectsWrongCoordinateLength() throws Exception {
		KeyPair keyPair = generateEcKey("secp256r1");
		ECPublicKey ecKey = (ECPublicKey) keyPair.getPublic();
		// Pad the x coordinate to 33 bytes instead of the expected 32 to trigger the length check.
		byte[] xOverlong = new byte[33];
		System.arraycopy(toUnsignedFixedLength(ecKey.getW().getAffineX().toByteArray(), 32), 0,
				xOverlong, 1, 32);
		String x = base64Url(xOverlong);
		String y = base64Url(toUnsignedFixedLength(ecKey.getW().getAffineY().toByteArray(), 32));
		String jwks = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"bad-len\",\"alg\":\"ES256\","
				+ "\"crv\":\"P-256\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}]}";

		JsonWebKey jwk = JsonWebKeySetFactory.createFromJson(jwks)
				.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.ES256, "bad-len");

		assertThatThrownBy(jwk::getPublicKey)
				.isInstanceOf(InvalidKeySpecException.class)
				.hasMessageContaining("must be 32 octets each");
	}

	private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		return generator.generateKeyPair();
	}

	private static KeyPair generateEcKey(String nistCurve) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec(nistCurve));
		return generator.generateKeyPair();
	}

	private static String buildRsaJwks(String alg, String kid, KeyPair keyPair) {
		RSAPublicKey rsa = (RSAPublicKey) keyPair.getPublic();
		String n = base64Url(stripLeadingZero(rsa.getModulus().toByteArray()));
		String e = base64Url(stripLeadingZero(rsa.getPublicExponent().toByteArray()));
		return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"" + kid + "\",\"alg\":\"" + alg
				+ "\",\"n\":\"" + n + "\",\"e\":\"" + e + "\"}]}";
	}

	private static String buildEcJwks(String alg, String crv, String kid, KeyPair keyPair, int coordLen) {
		ECPublicKey ec = (ECPublicKey) keyPair.getPublic();
		String x = base64Url(toUnsignedFixedLength(ec.getW().getAffineX().toByteArray(), coordLen));
		String y = base64Url(toUnsignedFixedLength(ec.getW().getAffineY().toByteArray(), coordLen));
		return "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"" + kid + "\",\"alg\":\"" + alg
				+ "\",\"crv\":\"" + crv + "\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}]}";
	}

	private static byte[] stripLeadingZero(byte[] bytes) {
		if (bytes.length > 1 && bytes[0] == 0) {
			byte[] out = new byte[bytes.length - 1];
			System.arraycopy(bytes, 1, out, 0, out.length);
			return out;
		}
		return bytes;
	}

	private static byte[] toUnsignedFixedLength(byte[] bytes, int length) {
		byte[] unsigned = stripLeadingZero(bytes);
		if (unsigned.length == length) {
			return unsigned;
		}
		if (unsigned.length > length) {
			throw new IllegalStateException("coordinate longer than expected");
		}
		byte[] padded = new byte[length];
		System.arraycopy(unsigned, 0, padded, length - unsigned.length, unsigned.length);
		return padded;
	}

	private static String base64Url(byte[] bytes) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	// A syntactically valid RSA JWK reused in the tolerance tests below to prove that valid entries
	// survive alongside entries the library cannot use.
	private static final String RSA_ENTRY = "{"
			+ "\"kty\":\"RSA\","
			+ "\"alg\":\"RS256\","
			+ "\"kid\":\"rsa-key\","
			+ "\"e\":\"AQAB\","
			+ "\"n\":\"AJjTNzl32UtFLvHmGVwoBlhYFVkF-jB52nWJN8x2eTyD3g2NwKWkhqTBIlcJ9XE-ilFRzCx3Js9YLDcu"
			+ "-KQp5gmttluydwaGbpc0dAN-2sjFa0R4d5334MkpPLufNZdNm723KWm93txKLUjeS4sRk9VVmbw22pV3-p-ZKuOfTVi"
			+ "-mc5BLNtDKzhJOXC3Z7IoE0FB0iiEOU6ZXcg5CTJts8DpawdkffOPkHZQxZqFR-2Gro8a9oNGferu1vSJopOsE4hXPFu"
			+ "3lF34Txp-63lS6tf-aNjc9CcdHoxRw8Exp3LPpNUQUug26UzjK_bZCRHN2bF9xbeDragpEVyOYVJmvh8\""
			+ "}";

	@Test
	public void skipsJwksEntryWithUnsupportedAlgValue() {
		// "EdDSA" is not part of the supported set. The unusable entry must be silently dropped so
		// the RSA key alongside it remains validatable.
		String jwks = "{\"keys\":["
				+ "{\"kty\":\"OKP\",\"alg\":\"EdDSA\",\"kid\":\"ed-key\",\"crv\":\"Ed25519\",\"x\":\"foo\"},"
				+ RSA_ENTRY
				+ "]}";

		JsonWebKeySet result = JsonWebKeySetFactory.createFromJson(jwks);

		assertThat(result.getAll()).hasSize(1);
		assertThat(result.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "rsa-key")).isNotNull();
	}

	@Test
	public void skipsJwksEntryWithUnsupportedKty() {
		// No "alg" present; kty "OKP" (EdDSA family) does not resolve to any supported signature algorithm.
		String jwks = "{\"keys\":["
				+ "{\"kty\":\"OKP\",\"kid\":\"ed-key\",\"crv\":\"Ed25519\",\"x\":\"foo\"},"
				+ RSA_ENTRY
				+ "]}";

		JsonWebKeySet result = JsonWebKeySetFactory.createFromJson(jwks);

		assertThat(result.getAll()).hasSize(1);
		assertThat(result.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "rsa-key")).isNotNull();
	}

	@Test
	public void skipsJwksEntryWithMissingKty() {
		// Entirely malformed entry (missing mandatory "kty") must not tear down the whole set.
		String jwks = "{\"keys\":["
				+ "{\"kid\":\"broken\"},"
				+ RSA_ENTRY
				+ "]}";

		JsonWebKeySet result = JsonWebKeySetFactory.createFromJson(jwks);

		assertThat(result.getAll()).hasSize(1);
		assertThat(result.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "rsa-key")).isNotNull();
	}
}
