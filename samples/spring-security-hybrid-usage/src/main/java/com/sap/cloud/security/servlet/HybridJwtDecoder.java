package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.Optional;

public class HybridJwtDecoder implements JwtDecoder {
    CombiningValidator<Token> xsuaaTokenValidators;
    CombiningValidator<Token> iasTokenValidators;


    public HybridJwtDecoder(CombiningValidator<Token> xsuaaValidator, CombiningValidator<Token> iasValidator) {
        xsuaaTokenValidators = xsuaaValidator;
        iasTokenValidators = iasValidator;
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
