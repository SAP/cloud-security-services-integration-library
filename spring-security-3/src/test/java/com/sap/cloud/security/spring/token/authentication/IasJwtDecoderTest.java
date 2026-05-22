/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.x509.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.x509.X509Constants.FWD_CLIENT_CERT_HEADER;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class IasJwtDecoderTest {

	JwtGenerator jwtGenerator = JwtGenerator.getInstance(IAS, "theClientId");
	IasJwtDecoder cut;

	@BeforeEach
	void setup() {
		CombiningValidator<Token> combiningValidator = Mockito.mock(CombiningValidator.class);
		when(combiningValidator.validate(any())).thenReturn(ValidationResults.createValid());

		cut = new IasJwtDecoder(combiningValidator);
	}

	@Test
	void parseJwt() {
		Jwt jwt = IasJwtDecoder.parseJwt(jwtGenerator.createToken());

		assertEquals(2, jwt.getHeaders().size());
		assertEquals(8, jwt.getClaims().size());
		assertEquals(1, jwt.getExpiresAt().compareTo(Instant.now()));
		assertEquals("theClientId", jwt.getClaim(TokenClaims.AUTHORIZATION_PARTY));
	}

	@Test
	void decodeIasTokenWithoutValidators() {
		String encodedToken = jwtGenerator.createToken().getTokenValue();
		assertEquals("theClientId", cut.decode(encodedToken).getClaim(TokenClaims.AUTHORIZATION_PARTY));
	}

	@Test
	void decodeIasTokenWithProofToken() throws IOException {
		String cert = IOUtils.resourceToString("/certificate.txt", StandardCharsets.UTF_8);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(FWD_CLIENT_CERT_HEADER, cert);
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

		String encodedToken = jwtGenerator.createToken().getTokenValue();
		assertEquals("theClientId", cut.decode(encodedToken).getClaim(TokenClaims.AUTHORIZATION_PARTY));
		assertNotNull(SecurityContext.getClientCertificate());
	}

	@Test
	void decodeIasTokenWithoutFwdCert() {
		ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
		Logger logger = (Logger) LoggerFactory.getLogger(X509Certificate.class);
		listAppender.start();
		logger.addAppender(listAppender);
		MockHttpServletRequest request = new MockHttpServletRequest();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

		String encodedToken = jwtGenerator.createToken().getTokenValue();
		cut.decode(encodedToken);
		Assertions.assertThat(listAppender.list).isEmpty();
		listAppender.stop();
	}

	@Test
	void decodeInvalidToken_throwsAccessDeniedException() {
		CombiningValidator<Token> combiningValidator = Mockito.mock(CombiningValidator.class);
		when(combiningValidator.validate(any())).thenReturn(ValidationResults.createInvalid("error"));
		cut = new IasJwtDecoder(combiningValidator);
		String encodedToken = jwtGenerator.createToken().getTokenValue();

		assertThrows(BadJwtException.class, () -> cut.decode(encodedToken));
	}

	@Test
	void decodeWithMissingExpClaim_throwsBadJwtException() {
		String encodedToken = jwtGenerator
				.withClaimValue(TokenClaims.EXPIRATION, "")
				.createToken().getTokenValue();

		assertThrows(BadJwtException.class, () -> cut.decode(encodedToken));
	}

	@Test
	void decodeWithCorruptToken_throwsBadJwtException() {
		assertThrows(BadJwtException.class, () -> cut.decode("Bearer e30="));
		assertThrows(BadJwtException.class, () -> cut.decode("Bearer"));
		assertThrows(BadJwtException.class, () -> cut.decode(null));
		assertThrows(BadJwtException.class, () -> cut.decode("Bearerabc"));
	}

}