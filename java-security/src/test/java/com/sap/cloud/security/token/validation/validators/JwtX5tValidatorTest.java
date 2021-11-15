package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.x509.X509Constants;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.internal.util.collections.Sets;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(SystemStubsExtension.class)
class JwtX5tValidatorTest {

	private static final JwtX5tValidator CUT = new JwtX5tValidator();
	public static final String X5T_VALIDATOR_DISABLED = "X5tValidator is not enabled";
	private static String tokenWithX5t;
	private static String tokenWithInvalidX5t;
	private static final Token TOKEN = Mockito.mock(Token.class);
	private static String x509;
	private static final String INVALID_MESSAGE = "Certificate validation failed";

	@BeforeAll
	static void beforeAll() throws IOException {
		tokenWithX5t = IOUtils.resourceToString("/iasTokenWithCnfRSA256.txt", StandardCharsets.UTF_8);
		tokenWithInvalidX5t = IOUtils.resourceToString("/iasTokenInvalidCnfRSA256.txt", StandardCharsets.UTF_8);
		x509 = IOUtils.resourceToString("/cf-forwarded-client-cert.txt", StandardCharsets.UTF_8);
	}

	@AfterEach
	void afterEach(EnvironmentVariables environmentVariables) throws Exception {
		environmentVariables.teardown();
		SecurityContext.clear();
	}

	@Test
	void validateToken_WithValidCnf_validX509(EnvironmentVariables environmentVariables) {
		environmentVariables.set(X509Constants.X5T_VALIDATOR_ENABLED, "true");
		Token token = Token.create(tokenWithX5t);
		SecurityContext.setClientCertificate(x509);
		ValidationResult result = CUT.validate(token);
		assertTrue(result.isValid());
	}

	@Test
	void validateToken_WithInvalidCnf_validX509(EnvironmentVariables environmentVariables) {
		environmentVariables.set(X509Constants.X5T_VALIDATOR_ENABLED, "true");
		Token token = Token.create(tokenWithInvalidX5t);
		SecurityContext.setClientCertificate(x509);
		ValidationResult result = CUT.validate(token);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

	@Test
	void validateToken_WithInvalidCnf_invalidX509(EnvironmentVariables environmentVariables) {
		environmentVariables.set(X509Constants.X5T_VALIDATOR_ENABLED, "true");
		Token token = Token.create(tokenWithInvalidX5t);
		SecurityContext.setClientCertificate("x509");
		ValidationResult result = CUT.validate(token);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

	@Disabled("until proofOfPossesion validator subchain is implemented")
	@Test
	void validateToken_validatorDisabled(EnvironmentVariables environmentVariables) {
		environmentVariables.set(X509Constants.X5T_VALIDATOR_ENABLED, "false");
		Token token = Token.create(tokenWithX5t);
		ValidationResult result = CUT.validate(token);
		assertTrue(result.isErroneous());
		assertEquals(X5T_VALIDATOR_DISABLED, result.getErrorDescription());
	}

	@Disabled("until aud claim validation is clarified")
	@Test
	void validateToken_NoCnfSingleAud() {
		Mockito.when(TOKEN.getAudiences()).thenReturn(Sets.newSet("myClientId"));
		ValidationResult result = CUT.validate(TOKEN);
		assertTrue(result.isValid());
	}

	@Disabled("until aud claim validation is clarified")
	@Test
	void validateToken_NoCnfMultipleAud() {
		Mockito.when(TOKEN.getAudiences()).thenReturn(Sets.newSet("aud1", "aud2"));
		ValidationResult result = CUT.validate(TOKEN);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

	@Disabled("until aud claim validation is clarified")
	@Test
	void validateToken_NoCnfEmptyAud() {
		Mockito.when(TOKEN.getAudiences()).thenReturn(Collections.emptySet());
		ValidationResult result = CUT.validate(TOKEN);
		assertTrue(result.isErroneous());
		assertEquals(INVALID_MESSAGE, result.getErrorDescription());
	}

}