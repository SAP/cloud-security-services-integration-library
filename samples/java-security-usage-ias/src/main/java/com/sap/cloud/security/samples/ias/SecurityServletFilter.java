package com.sap.cloud.security.samples.ias;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.servlet.OAuth2SecurityFilter;
import com.sap.cloud.security.token.IasToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;


import javax.servlet.annotation.WebFilter;

@WebFilter
public class SecurityServletFilter extends OAuth2SecurityFilter {

    private OAuth2SecurityFilter.TokenExtractor iasTokenExtractor = (authorizationHeader) -> new IasToken(authorizationHeader);

    public SecurityServletFilter() {
        super();
    }

    @Override
    protected Validator<Token> getOrCreateTokenValidator() {
        if (tokenValidator == null) {
            tokenValidator = JwtValidatorBuilder
                    .getInstance(Environments.getCurrent().getIasConfiguration())
                    //.withOAuth2TokenKeyService(tokenKeyService)
                    //.withOidcConfigurationService(oidcConfigurationService)
                    .build();
        }
        return tokenValidator;
    }

}
