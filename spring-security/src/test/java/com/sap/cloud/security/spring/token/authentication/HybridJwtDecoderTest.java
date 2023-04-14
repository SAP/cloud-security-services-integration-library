/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
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
import static com.sap.cloud.security.config.Service.XSUAA;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class HybridJwtDecoderTest {
	JwtGenerator jwtGenerator = JwtGenerator.getInstance(IAS, "theClientId");
	CombiningValidator<Token> combiningValidator;
	HybridJwtDecoder cut;

	@BeforeEach
	void setup() {
		combiningValidator = Mockito.mock(CombiningValidator.class);
		when(combiningValidator.validate(any())).thenReturn(ValidationResults.createValid());

		cut = new HybridJwtDecoder(combiningValidator, combiningValidator);
	}

	@Test
	void parseJwt() {
		Jwt jwt = HybridJwtDecoder.parseJwt(jwtGenerator.createToken());

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
	void decodeXsuaaTokenWithoutValidators() {
		String encodedToken = JwtGenerator.getInstance(XSUAA, "theClientId").createToken().getTokenValue();
		assertEquals("theClientId", cut.decode(encodedToken).getClaim(TokenClaims.AUTHORIZATION_PARTY));
	}

	@Test
	void decodeInvalidToken_throwsAccessDeniedException() {
		when(combiningValidator.validate(any())).thenReturn(ValidationResults.createInvalid("error"));
		cut = new HybridJwtDecoder(combiningValidator, combiningValidator);
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

	@Test
	void instantiateForXsuaaOnly() {
		cut = new HybridJwtDecoder(combiningValidator, null);

		// IAS token can't be validated
		String encodedIasToken = jwtGenerator.createToken().getTokenValue();
		assertThrows(BadJwtException.class, () -> cut.decode(encodedIasToken));

		// XSUAA token can be validated
		String encodedXsuaaToken = JwtGenerator.getInstance(XSUAA, "theClientId").createToken().getTokenValue();
		assertEquals("theClientId", cut.decode(encodedXsuaaToken).getClaim(TokenClaims.AUTHORIZATION_PARTY));

	}
}