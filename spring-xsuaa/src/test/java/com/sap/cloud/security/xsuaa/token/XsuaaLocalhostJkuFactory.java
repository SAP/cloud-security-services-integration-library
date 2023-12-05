package com.sap.cloud.security.xsuaa.token;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.token.validation.XsuaaJkuFactory;

import java.text.ParseException;

public class XsuaaLocalhostJkuFactory implements XsuaaJkuFactory {

    @Override
    public String create(String token) {
        String tokenJku;
        try {
            JWT jwt = JWTParser.parse(token);
            tokenJku = (String) jwt.getHeader().toJSONObject().get(TokenHeader.JWKS_URL);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }

        if (tokenJku == null || tokenJku.contains("localhost") || tokenJku.contains("127.0.0.1")) {
            return tokenJku;
        }

        throw new IllegalArgumentException("JKU is not trusted because it does not target localhost.");
    }
}