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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class ReactiveHybridJwtDecoderTest {

	JwtGenerator jwtGenerator;
	CombiningValidator<Token> combiningValidator;
	ReactiveHybridJwtDecoder cut;

	@BeforeEach
	void setUp() {
		jwtGenerator = JwtGenerator.getInstance(IAS, "theClientId");
		combiningValidator = Mockito.mock(CombiningValidator.class);
		when(combiningValidator.validate(any())).thenReturn(ValidationResults.createValid());

		cut = new ReactiveHybridJwtDecoder(combiningValidator, combiningValidator);
	}

	@Test
	void parseJwt() {
		Jwt jwtToken = ReactiveHybridJwtDecoder.parseJwt(jwtGenerator.createToken()).block();

		assertEquals(2, jwtToken.getHeaders().size());
		assertEquals(8, jwtToken.getClaims().size());
		assertEquals(1, jwtToken.getExpiresAt().compareTo(Instant.now()));
		assertEquals("theClientId", jwtToken.getClaims().get(TokenClaims.AUTHORIZATION_PARTY));

	}

	@Test
	void decodeXsuaaTokenWithIatClaim() {
		String encodedToken = JwtGenerator.getInstance(XSUAA, "theClientId").withClaimValue("iat", "1704067200").createToken().getTokenValue();

		assertEquals("theClientId", cut.decode(encodedToken).block().getClaim(TokenClaims.AUTHORIZATION_PARTY));
	}

	@Test
	void decodeIasTokenWithoutValidators() {
		String encodedToken = jwtGenerator.createToken().getTokenValue();

		assertEquals("theClientId", cut.decode(encodedToken).block().getClaim(TokenClaims.AUTHORIZATION_PARTY));
	}

	@Test
	void decodeXsuaaTokenWithoutValidators() {
		String encodedToken = JwtGenerator.getInstance(XSUAA, "theClientId").createToken().getTokenValue();

		assertEquals("theClientId", cut.decode(encodedToken).block().getClaim(TokenClaims.AUTHORIZATION_PARTY));
	}

	@Test
	void decodeInvalidToken_throwsAccessDeniedException() {
		when(combiningValidator.validate(any())).thenReturn(ValidationResults.createInvalid("error"));
		cut = new ReactiveHybridJwtDecoder(combiningValidator, combiningValidator);
		String encodedToken = jwtGenerator.createToken().getTokenValue();

		assertThrows(BadJwtException.class, () -> cut.decode(encodedToken).block());
	}

	@Test
	void decodeWithMissingExpClaim_throwsBadJwtException() {
		String encodedToken = jwtGenerator
				.withClaimValue(TokenClaims.EXPIRATION, "")
				.createToken().getTokenValue();

		assertThrows(BadJwtException.class, () -> cut.decode(encodedToken).block());
	}

	@Test
	void decodeWithMissingIatClaim_throwsBadJwtException() {
		String encodedToken = jwtGenerator
				.withClaimValue(TokenClaims.XSUAA.ISSUED_AT, "")
				.createToken().getTokenValue();

		assertThrows(BadJwtException.class, () -> cut.decode(encodedToken).block());
	}

	@Test
	void decodeWithCorruptToken_throwsBadJwtException() {
		assertThrows(BadJwtException.class, () -> cut.decode("Bearer e30=").block());
		assertThrows(BadJwtException.class, () -> cut.decode("Bearer").block());
		assertThrows(BadJwtException.class, () -> cut.decode(null).block());
		assertThrows(BadJwtException.class, () -> cut.decode("Bearerabc").block());
	}
}
