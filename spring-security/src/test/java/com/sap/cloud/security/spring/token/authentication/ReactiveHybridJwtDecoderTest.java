package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResults;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.BadJwtException;

import java.time.Instant;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ReactiveHybridJwtDecoderTest {

    JwtGenerator jwtGenerator = JwtGenerator.getInstance(IAS, "theClientId");
    CombiningValidator<Token> combiningValidator;
    ReactiveHybridJwtDecoder cut;

    @Before
    public void setUp(){
        combiningValidator = Mockito.mock(CombiningValidator.class);
        when(combiningValidator.validate(any())).thenReturn(ValidationResults.createValid());

        cut = new ReactiveHybridJwtDecoder(combiningValidator, combiningValidator);
    }

    @Test
    public void parseJwt(){
        Jwt jwtToken = ReactiveHybridJwtDecoder.parseJwt(jwtGenerator.createToken()).block();

        assertEquals(2, jwtToken.getHeaders().size());
        assertEquals(8, jwtToken.getClaims().size());
        assertEquals(1, jwtToken.getExpiresAt().compareTo(Instant.now()));
        assertEquals("theClientId", jwtToken.getClaims().get(TokenClaims.AUTHORIZATION_PARTY));

    }

    @Test
    public void decodeIasTokenWithoutValidators(){
        String encodedToken = jwtGenerator.createToken().getTokenValue();

        assertEquals("theClientId", cut.decode(encodedToken).block().getClaim(TokenClaims.AUTHORIZATION_PARTY));
    }

    @Test
    public void decodeXsuaaTokenWithoutValidators(){
        String encodedToken = JwtGenerator.getInstance(XSUAA, "theClientId").createToken().getTokenValue();

        assertEquals("theClientId", cut.decode(encodedToken).block().getClaim(TokenClaims.AUTHORIZATION_PARTY));
    }

    @Test
    public void decodeInvalidToken_throwsAccessDeniedException() {
        when(combiningValidator.validate(any())).thenReturn(ValidationResults.createInvalid("error"));
        cut = new ReactiveHybridJwtDecoder(combiningValidator, combiningValidator);
        String encodedToken = jwtGenerator.createToken().getTokenValue();

        assertThrows(BadJwtException.class, () -> cut.decode(encodedToken).block());
    }

    @Test
    public void decodeWithMissingExpClaim_throwsBadJwtException() {
        String encodedToken = jwtGenerator
                .withClaimValue(TokenClaims.EXPIRATION, "")
                .createToken().getTokenValue();

        assertThrows(BadJwtException.class, () -> cut.decode(encodedToken).block());
    }

    @Test
    public void decodeWithMissingIatClaim_throwsBadJwtException(){
        String encodedToken = jwtGenerator
                .withClaimValue(TokenClaims.XSUAA.ISSUED_AT, "")
                .createToken().getTokenValue();

        assertThrows(BadJwtException.class, () -> cut.decode(encodedToken).block());
    }

    @Test
    public void decodeWithCorruptToken_throwsBadJwtException() {
        assertThrows(BadJwtException.class, () -> cut.decode("Bearer e30=").block());
        assertThrows(BadJwtException.class, () -> cut.decode("Bearer").block());
        assertThrows(BadJwtException.class, () -> cut.decode(null).block());
        assertThrows(BadJwtException.class, () -> cut.decode("Bearerabc").block());
    }
}
