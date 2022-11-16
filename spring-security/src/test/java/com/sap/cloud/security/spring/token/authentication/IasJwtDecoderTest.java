/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResults;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;

import static com.sap.cloud.security.config.Service.IAS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
		assertEquals(7, jwt.getClaims().size());
		assertEquals(1, jwt.getExpiresAt().compareTo(Instant.now()));
		assertEquals("theClientId", jwt.getClaim(TokenClaims.AUTHORIZATION_PARTY));
	}

	@Test
	void decodeIasTokenWithoutValidators() {
		String encodedToken = jwtGenerator.createToken().getTokenValue();
		assertEquals("theClientId", cut.decode(encodedToken).getClaim(TokenClaims.AUTHORIZATION_PARTY));
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