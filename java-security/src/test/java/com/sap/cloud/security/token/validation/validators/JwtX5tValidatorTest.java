/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.x509.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.internal.util.collections.Sets;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtX5tValidatorTest {

	private static JwtX5tValidator CUT;
	private static String tokenWithX5t;
	private static String tokenWithInvalidX5t;
	private static X509Certificate x509;
	private static final Token TOKEN = Mockito.mock(Token.class);
	private static final JsonObject JSON_MOCK = Mockito.mock(JsonObject.class);
	private static final String INVALID_MESSAGE = "Certificate validation failed";
	private static final String X5T_VALIDATOR_DISABLED = "X5tValidator is not enabled";

	@BeforeAll
	static void beforeAll() throws IOException {
		tokenWithX5t = IOUtils.resourceToString("/iasTokenWithCnfRSA256.txt", StandardCharsets.UTF_8);
		tokenWithInvalidX5t = IOUtils.resourceToString("/iasTokenInvalidCnfRSA256.txt", StandardCharsets.UTF_8);
		x509 = X509Certificate
				.newCertificate(IOUtils.resourceToString("/cf-forwarded-client-cert.txt", StandardCharsets.UTF_8));
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withClientId("myClientId")
				.build();
		CUT = new JwtX5tValidator(configuration);
		Mockito.when(JSON_MOCK.getAsString(TokenClaims.CNF_X5T)).thenReturn("fU-XoQlhMTpQsz9ArXl6zHIpMGuRO4ExLKdLRTc5VjM");
	}

	@Test
	void validateToken_ValidToken_validX509() {
		Token token = Token.create(tokenWithX5t);
		SecurityContext.setClientCertificate(x509);
		ValidationResult result = CUT.validate(token);
		assertTrue(result.isValid());
	}

	@Test
	void validateToken_ValidToken_invalidX509() {
		Token token = Token.create(tokenWithX5t);
		SecurityContext.setClientCertificate(null);
		ValidationResult result = CUT.validate(token);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

	@Test
	void validateToken_validCnf_validX509_MultipleAud() {
		SecurityContext.setClientCertificate(x509);
		Mockito.when(TOKEN.getAudiences()).thenReturn(Sets.newSet("aud1", "aud2"));
		Mockito.when(TOKEN.getClaimAsJsonObject(TokenClaims.CNF)).thenReturn(JSON_MOCK);
		ValidationResult result = CUT.validate(TOKEN);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

	@Test
	void validateToken_validCnf_validX509_EmptyAud() {
		SecurityContext.setClientCertificate(x509);
		Mockito.when(TOKEN.getAudiences()).thenReturn(Collections.emptySet());
		Mockito.when(TOKEN.getClaimAsJsonObject(TokenClaims.CNF)).thenReturn(JSON_MOCK);
		ValidationResult result = CUT.validate(TOKEN);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

	@Test
	void validateToken_InvalidCnf_validX509() {
		Token token = Token.create(tokenWithInvalidX5t);
		SecurityContext.setClientCertificate(x509);
		ValidationResult result = CUT.validate(token);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

	@Test
	void validateToken_InvalidCnf_invalidX509() {
		Token token = Token.create(tokenWithInvalidX5t);
		SecurityContext.setClientCertificate(null);
		ValidationResult result = CUT.validate(token);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

	@Test
	void validateToken_NoCnf_validAud() {
		Mockito.when(JSON_MOCK.getAsString(TokenClaims.CNF_X5T)).thenReturn(null);
		Mockito.when(TOKEN.getAudiences()).thenReturn(Sets.newSet("myClientId"));
		ValidationResult result = CUT.validate(TOKEN);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

	@Test
	void validateToken_NoCnf_MultipleAud() {
		Mockito.when(JSON_MOCK.getAsString(TokenClaims.CNF_X5T)).thenReturn(null);
		Mockito.when(TOKEN.getAudiences()).thenReturn(Sets.newSet("aud1", "aud2"));
		ValidationResult result = CUT.validate(TOKEN);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

	@Test
	void validateToken_NoCnf_EmptyAud() {
		Mockito.when(JSON_MOCK.getAsString(TokenClaims.CNF_X5T)).thenReturn(null);
		Mockito.when(TOKEN.getAudiences()).thenReturn(Collections.emptySet());
		ValidationResult result = CUT.validate(TOKEN);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

	@Disabled("until proofOfPossesion validator subchain is implemented")
	@Test
	void validateToken_validatorDisabled() {
		Token token = Token.create(tokenWithX5t);
		ValidationResult result = CUT.validate(token);
		assertTrue(result.isErroneous());
		assertEquals(X5T_VALIDATOR_DISABLED, result.getErrorDescription());
	}

}