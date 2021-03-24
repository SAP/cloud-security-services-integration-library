package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.internal.util.collections.Sets;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtCnfValidatorTest {

	private static final JwtCnfValidator CUT = new JwtCnfValidator("myClientId");
	private static String tokenWithCnf;
	private static String tokenWithCnf2;
	private static final Token TOKEN = Mockito.mock(Token.class);
	private static String x509;

	@BeforeAll
	static void beforeAll() throws IOException {
		tokenWithCnf = IOUtils.resourceToString("/iasTokenWithCnfRSA256.txt", StandardCharsets.UTF_8);
		tokenWithCnf2 = IOUtils.resourceToString("/iasTokenInvalidCnfRSA256.txt", StandardCharsets.UTF_8);
		x509 = IOUtils.resourceToString("/x509Base64.txt", StandardCharsets.UTF_8);
	}

	@AfterEach
	void afterEach() {
		SecurityContext.clear();
	}

	@Test
	void validateToken_WithValidCnf(){
		Token token = Token.create(tokenWithCnf);
		SecurityContext.setCertificate(x509);
		ValidationResult result = CUT.validate(token);
		assertTrue(result.isValid());
	}


	@Test
	void validateToken_WithInvalidCnf(){
		Token token = Token.create(tokenWithCnf2);
		SecurityContext.setCertificate(x509);
		ValidationResult result = CUT.validate(token);
		assertFalse(result.isValid());
	}

	@Test
	void validateToken_NoCnfValidAud(){
		Mockito.when(TOKEN.getAudiences()).thenReturn(Sets.newSet("myClientId"));
		ValidationResult result = CUT.validate(TOKEN);
		assertTrue(result.isValid());
	}

	@Test
	void validateToken_NoCnfMultipleAud() {
		Mockito.when(TOKEN.getAudiences()).thenReturn(Sets.newSet("aud1","aud2"));
		ValidationResult result = CUT.validate(TOKEN);
		assertFalse(result.isValid());
	}

	@Test
	void validateToken_NoCnfEmptyAud() {
		Mockito.when(TOKEN.getAudiences()).thenReturn(Collections.emptySet());
		ValidationResult result = CUT.validate(TOKEN);
		assertFalse(result.isValid());
	}

	@Test
	void validateToken_NoCnfInvalidAud() {
		Mockito.when(TOKEN.getAudiences()).thenReturn(Sets.newSet("aud"));
		ValidationResult result = CUT.validate(TOKEN);
		assertFalse(result.isValid());
	}
}