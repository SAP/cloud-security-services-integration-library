package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.InvalidTokenException;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;


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
        ValidationResult validationResult;

        // TODO
        switch (token.getService()) {
            case IAS:
                validationResult = iasTokenValidators.validate(token);
                break;
            case XSUAA:
                validationResult = xsuaaTokenValidators.validate(token);
                break;
            default:
                throw new InvalidTokenException("The token is invalid");
        }
        if(validationResult.isErroneous()) {
            throw new InvalidTokenException("The token is invalid: " + validationResult.getErrorDescription());
        }
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
