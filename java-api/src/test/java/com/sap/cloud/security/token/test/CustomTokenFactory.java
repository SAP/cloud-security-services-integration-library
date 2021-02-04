package com.sap.cloud.security.token.test;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenFactory;
import org.mockito.Mockito;

public class CustomTokenFactory implements TokenFactory {
    @Override
    public Token create(String jwtToken) {
        return Mockito.mock(Token.class);
    }
}
