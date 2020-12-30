package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

public class HybridJwtDecoder implements JwtDecoder {

    public HybridJwtDecoder() {

    }

    @Override
    public Jwt decode(String encodedToken) throws JwtException {
        Token token = TokenFactory.create(encodedToken);
        return parseJwt(token);
    }

    /**
     * Parses decoded Jwt token to {@link Jwt}
     *
     * @param token
     *            the token
     * @return Jwt class
     */
    static Jwt parseJwt(Token token) {
        return new Jwt(token.getTokenValue(), token.getNotBefore(), token.getExpiration(),
                token.getHeaders(), token.getClaims());
    }
}
