package com.sap.cloud.security.token;

public class XsuaaLocalhostJkuFactory implements XsuaaJkuFactory {

    @Override
    public String create(String jwt) {
        Token token = Token.create(jwt);
        String tokenJku = (String) token.getHeaders().get(TokenHeader.JWKS_URL);

        if (tokenJku.contains("localhost") || tokenJku.contains("127.0.0.1")) {
            return tokenJku;
        }

        throw new IllegalArgumentException("JKU is not trusted because it does not target localhost.");
    }
}