package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

public class ReactiveHybridJwtDecoder implements ReactiveJwtDecoder {

    final CombiningValidator<Token> xsuaaTokenValidators;
    final CombiningValidator<Token> iasTokenValidators;
    private final Logger logger = LoggerFactory.getLogger(getClass());

    public ReactiveHybridJwtDecoder(CombiningValidator<Token> xsuaaTokenValidators, CombiningValidator<Token> iasTokenValidators) {
        this.xsuaaTokenValidators = xsuaaTokenValidators;
        this.iasTokenValidators = iasTokenValidators;
    }

    @Override
    public Mono<Jwt> decode(String encodedToken) throws JwtException {
        return Mono.just(encodedToken)
                .filter(token -> StringUtils.hasText(token))
                .switchIfEmpty(Mono.error(new BadJwtException("encoded Token must neither be null nor empty String.")))
                .map(Token::create)
                .flatMap(token -> {
                    Mono<Jwt> jwt = parseJwt(token);
                    Mono<ValidationResult> validationResult;

                    switch (token.getService()){
                        case IAS:
                            if (iasTokenValidators == null){
                                return Mono.error(new BadJwtException("Tokens issued by IAS service aren't accepted"));
                            }
                            validationResult = (Mono<ValidationResult>) iasTokenValidators.validate(token);
                            break;
                        case XSUAA:
                            validationResult = (Mono<ValidationResult>) xsuaaTokenValidators.validate(token);
                            break;
                        default:
                            return Mono.error(new BadJwtException("Tokens issued by " + token.getService() + " service aren´t supported."));
                    }
                    return validationResult
                            .filter(vr -> !vr.isErroneous())
                            .switchIfEmpty(Mono.error(new BadJwtException("The token is invalid: " + validationResult.block().getErrorDescription())))
                            .doOnNext(result -> logger.debug("Token issued by {} service was succesfully validated.", token.getService()))
                            .then(jwt);
                })
                .onErrorMap(RuntimeException.class, ex -> new BadJwtException("Error initializing JWT decoder: " + ex.getMessage(), ex));
    }

    public static Mono<Jwt> parseJwt(Token token) {
        return Mono.just(new Jwt(token.getTokenValue(), token.getNotBefore(), token.getExpiration(),
                token.getHeaders(), token.getClaims()));
    }
}
