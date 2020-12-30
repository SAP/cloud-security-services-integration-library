package com.sap.cloud.security.authentication;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import org.json.JSONObject;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class HybridJwtDecoder implements JwtDecoder {

    public HybridJwtDecoder() {

    }

    @Override
    public Jwt decode(String s) throws JwtException {
        return null;
    }

    private Jwt convertToJwt(Token token) {
        Map<String, Object> claims = new HashMap<>();

        Jwt jwt = new Jwt(token.getTokenValue(), token.getNotBefore(), token.getExpiration(),
                Collections.EMPTY_MAP, claims);

        return jwt;
    }

    /**
     * Parses decoded Jwt token to org.springframework.security.oauth2.jwt
     *
     * @param decodedJwt
     *            decoded Jwt
     * @return Jwt class
     */
    static Jwt parseJwt(DecodedJwt decodedJwt) {
        JSONObject payload = new JSONObject(decodedJwt.getPayload());
        JSONObject header = new JSONObject(decodedJwt.getHeader());
        return new Jwt(decodedJwt.getEncodedToken(), Instant.ofEpochSecond(payload.getLong("iat")),
                Instant.ofEpochSecond(payload.getLong("exp")),
                header.toMap(), payload.toMap());
    }
}
