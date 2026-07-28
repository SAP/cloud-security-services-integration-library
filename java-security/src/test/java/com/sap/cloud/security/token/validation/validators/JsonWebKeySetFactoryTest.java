/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.core.IsEqual.equalTo;

public class JsonWebKeySetFactoryTest {

	// A syntactically valid RSA JWK (kty=RSA, alg=RS256, kid=rsa-key) that we reuse in the
	// unsupported-algorithm tests to prove that valid entries survive alongside unusable ones.
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

	private String jsonWebTokenKeys;

	@Before
	public void setup() throws IOException {
		jsonWebTokenKeys = IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Test
	public void getEmptyJsonWebKeySetWhenJsonIsNull() {
		assertThat(JsonWebKeySetFactory.createFromJson(null).getAll(), equalTo(Collections.EMPTY_SET));
	}

	@Test
	public void getKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "key-id-1");
		assertThat(jwk.getKeyAlgorithm().value(), equalTo("RS256"));
		assertThat(jwk.getKeyAlgorithm().type(), equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getKeyAlgorithm().type()));
		assertThat(jwk.getId(), equalTo("key-id-1"));
	}

	@Test
	public void getKeys() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "key-id-1");
		assertThat(jwk.getKeyAlgorithm().value(), equalTo("RS256"));
		assertThat(jwk.getKeyAlgorithm().type(), equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getKeyAlgorithm().type()));
		assertThat(jwk.getId(), equalTo("key-id-1"));
	}

	@Test
	public void getIasKeys() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		jsonWebTokenKeys = IOUtils.resourceToString("/iasJsonWebTokenKeys_noKid.json", StandardCharsets.UTF_8);
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jsonWebTokenKeys);
		JsonWebKey jwk = jwks.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, null);
		assertThat(jwk.getKeyAlgorithm().type(), equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getKeyAlgorithm().type()));
		assertThat(jwk.getId(), equalTo(JsonWebKey.DEFAULT_KEY_ID));
	}

	@Test
	public void skipsJwksEntryWithUnsupportedAlgValue() {
		// alg "ES256" (and kty "EC") is currently not supported by JwtSignatureAlgorithm.
		// The unusable entry must be silently dropped so RSA keys next to it remain validatable.
		String jwks = "{\"keys\":["
				+ "{\"kty\":\"EC\",\"alg\":\"ES256\",\"kid\":\"ec-key\",\"crv\":\"P-256\",\"x\":\"foo\",\"y\":\"bar\"},"
				+ RSA_ENTRY
				+ "]}";

		JsonWebKeySet result = JsonWebKeySetFactory.createFromJson(jwks);

		assertThat(result.getAll(), hasSize(1));
		assertThat(result.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "rsa-key"), notNullValue());
	}

	@Test
	public void skipsJwksEntryWithUnsupportedKty() {
		// No "alg" present, and kty "OKP" (EdDSA family) does not resolve to any supported signature algorithm.
		String jwks = "{\"keys\":["
				+ "{\"kty\":\"OKP\",\"kid\":\"ed-key\",\"crv\":\"Ed25519\",\"x\":\"foo\"},"
				+ RSA_ENTRY
				+ "]}";

		JsonWebKeySet result = JsonWebKeySetFactory.createFromJson(jwks);

		assertThat(result.getAll(), hasSize(1));
		assertThat(result.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "rsa-key"), notNullValue());
	}

	@Test
	public void skipsJwksEntryWithMissingKty() {
		// Entirely malformed entry (missing mandatory "kty") must not tear down the whole set.
		String jwks = "{\"keys\":["
				+ "{\"kid\":\"broken\"},"
				+ RSA_ENTRY
				+ "]}";

		JsonWebKeySet result = JsonWebKeySetFactory.createFromJson(jwks);

		assertThat(result.getAll(), hasSize(1));
		assertThat(result.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "rsa-key"), notNullValue());
	}
}
