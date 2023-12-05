package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenHeader;

/**
 * XsuaaLocalhostJkuFactory brings backward-compatibility for test credentials in consumer applications written before 2.17.0 that are used to validate java-security-test tokens.
 * This is necessary for successful JKU construction when 'localhost' is defined as uaadomain in the service credentials.
 * This class MUST NOT be loaded outside test scope and MUST be the ONLY implementation of {@link XsuaaJkuFactory}.
 */
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