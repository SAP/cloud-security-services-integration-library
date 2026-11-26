/**
 * SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation;

import static com.sap.cloud.security.config.ServiceConstants.XSUAA.UAA_DOMAIN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.servlet.XsuaaTokenAuthenticator;
import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.test.RSAKeys;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;

/** Verifies the production validation chain with java-security-test on the classpath, without network access. */
class XsuaaJkuTrustAnchorTest {

	private static final String CLIENT_ID = "sb-victim!t1";
	private static final String TENANT_ID = "attacker-tenant";
	private static final URI TRUSTED_JWKS = URI.create("https://trusted-auth.example.invalid/token_keys?zid=" + TENANT_ID);
	private RSAKeys trustedKeys;
	private RSAKeys attackerKeys;
	private SecurityHttpClient httpClient;
	private OAuth2ServiceConfiguration configuration;
	private CombiningValidator<Token> validator;

	@BeforeEach
	void setup() throws Exception {
		trustedKeys = RSAKeys.generate();
		attackerKeys = RSAKeys.generate();
		httpClient = mock(SecurityHttpClient.class);
		// Both endpoints are modelled: the vulnerable implementation would retrieve a valid attacker key.
		// All HTTP calls are intercepted; no DNS lookup or external/loopback request is performed.
		when(httpClient.execute(any())).thenAnswer(invocation -> {
			SecurityHttpRequest request = invocation.getArgument(0);
			RSAKeys keys = TRUSTED_JWKS.equals(request.getUri()) ? trustedKeys : attackerKeys;
			return new SecurityHttpResponse(200, Map.of(), jwks(keys));
		});
		configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(CLIENT_ID)
				.withUrl("https://tenant.trusted-auth.example.invalid")
				.withProperty(UAA_DOMAIN, "trusted-auth.example.invalid")
				.withProperty(ServiceConstants.XSUAA.APP_ID, "victim!t1")
				.withProperty("test-instance", UUID.randomUUID().toString())
				.build();
		validator = JwtValidatorBuilder.getInstance(configuration).withHttpClient(httpClient).build();
	}

	@AfterEach
	void cleanup() {
		SecurityContext.clear();
	}

	@ParameterizedTest
	@ValueSource(strings = {
			"https://localhost.attacker.example.invalid/jwks",
			"https://attacker.example.invalid/jwks?marker=localhost",
			"https://attacker.example.invalid/127.0.0.1/jwks",
			"http://localhost:12345/token_keys",
			"http://127.0.0.1:12345/token_keys"
	})
	void rejectsForgedTokenWithTestLibraryOnClasspath(String jku) throws Exception {
		Token token = token(attackerKeys).withHeaderParameter(TokenHeader.JWKS_URL, jku).createToken();
		ValidationResult result = validator.validate(token);
		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription()).contains("Signature of Jwt Token is not valid");
		verifyOnlyTrustedJwksWasRequested();
	}

	@Test
	void acceptsTrustedSignatureRegardlessOfUntrustedJkuHeader() throws Exception {
		Token token = token(trustedKeys)
				.withHeaderParameter(TokenHeader.JWKS_URL, "https://attacker.example.invalid/jwks?marker=localhost")
				.createToken();
		assertThat(validator.validate(token).isValid()).isTrue();
		verifyOnlyTrustedJwksWasRequested();
	}

	@Test
	void acceptsTrustedSignatureWithoutJkuHeader() throws Exception {
		Token token = token(trustedKeys).withHeaderParameter(TokenHeader.JWKS_URL, null).createToken();
		assertThat(token.hasHeaderParameter(TokenHeader.JWKS_URL)).isFalse();
		assertThat(validator.validate(token).isValid()).isTrue();
		verifyOnlyTrustedJwksWasRequested();
	}

	@Test
	void servletAuthenticatorRejectsForgedToken() throws Exception {
		Token token = token(attackerKeys)
				.withHeaderParameter(TokenHeader.JWKS_URL, "https://attacker.example.invalid/jwks?marker=localhost")
				.createToken();
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn("Bearer " + token.getTokenValue());
		XsuaaTokenAuthenticator authenticator = new XsuaaTokenAuthenticator();
		authenticator.withServiceConfiguration(configuration).withHttpClient(httpClient);

		assertThat(authenticator.validateRequest(request, mock(HttpServletResponse.class)).isAuthenticated()).isFalse();
		assertThat(SecurityContext.getToken()).isNull();
		verifyOnlyTrustedJwksWasRequested();
	}

	@Test
	void testArtifactDoesNotRegisterJkuFactory() {
		assertThat(getClass().getClassLoader().getResource("META-INF/services/" + XsuaaJkuFactory.class.getName()))
				.isNull();
	}

	private JwtGenerator token(RSAKeys keys) {
		return JwtGenerator.getInstance(Service.XSUAA, CLIENT_ID)
				.withPrivateKey(keys.getPrivate())
				.withExpiration(Instant.now().plusSeconds(600))
				.withClaimValue(TokenClaims.ISSUER, "https://attacker.example.invalid")
				.withClaimValue(TokenClaims.XSUAA.ZONE_ID, TENANT_ID)
				.withClaimValue(TokenClaims.USER_NAME, "attacker")
				.withScopes("victim!t1.Admin");
	}

	private void verifyOnlyTrustedJwksWasRequested() throws Exception {
		verify(httpClient).execute(argThat(request -> TRUSTED_JWKS.equals(request.getUri())));
		verifyNoMoreInteractions(httpClient);
	}

	private static String jwks(RSAKeys keys) {
		RSAPublicKey key = (RSAPublicKey) keys.getPublic();
		JSONObject jwk = new JSONObject().put("kty", "RSA").put("alg", "RS256").put("use", "sig")
				.put("kid", JwtGenerator.DEFAULT_KEY_ID).put("n", unsigned(key.getModulus()))
				.put("e", unsigned(key.getPublicExponent()));
		return new JSONObject().put("keys", new JSONArray().put(jwk)).toString();
	}

	private static String unsigned(BigInteger value) {
		byte[] bytes = value.toByteArray();
		return Base64.getUrlEncoder().withoutPadding()
				.encodeToString(bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes);
	}
}
