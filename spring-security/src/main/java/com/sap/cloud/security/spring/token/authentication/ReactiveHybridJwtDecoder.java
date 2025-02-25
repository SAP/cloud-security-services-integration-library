package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.time.Instant;

public class ReactiveHybridJwtDecoder implements ReactiveJwtDecoder {

	final CombiningValidator<Token> xsuaaTokenValidators;
	final CombiningValidator<Token> iasTokenValidators;
	private final Logger logger = LoggerFactory.getLogger(getClass());

	public ReactiveHybridJwtDecoder(CombiningValidator<Token> xsuaaTokenValidators,
			CombiningValidator<Token> iasTokenValidators) {
		this.xsuaaTokenValidators = xsuaaTokenValidators;
		this.iasTokenValidators = iasTokenValidators;
	}

	@Override
	public Mono<Jwt> decode(String encodedToken) throws JwtException {
		return Mono.justOrEmpty(encodedToken)
				.filter(StringUtils::hasText)
				.switchIfEmpty(Mono.error(new BadJwtException("Encoded Token must neither be null nor empty String.")))
				.map(Token::create)
				.flatMap(token -> {
					Mono<Jwt> jwt = parseJwt(token);
					ValidationResult validationResult;

					switch (token.getService()) {
					case IAS:
						if (iasTokenValidators == null) {
							return Mono.error(new BadJwtException("Tokens issued by IAS service aren't accepted"));
						}
						validationResult = iasTokenValidators.validate(token);
						break;
					case XSUAA:
						validationResult = xsuaaTokenValidators.validate(token);
						break;
					default:
						return Mono.error(new BadJwtException(
								"Tokens issued by " + token.getService() + " service aren´t supported."));
					}
					if (validationResult.isRetryable()) {
						return Mono.error(new JwtException(validationResult.getErrorDescription()));
					}
					if (validationResult.isErroneous()) {
						return Mono.error(new BadJwtException(
								"The token is invalid: " + validationResult.getErrorDescription()));
					}
					logger.debug("Token issued by {} service was successfully validated.", token.getService());
					return jwt;
				})
				.onErrorMap(RuntimeException.class,
						ex -> new BadJwtException("Error initializing JWT decoder: " + ex.getMessage(), ex));
	}

    static Mono<Jwt> parseJwt(Token token) {
        try{
            Instant issuedAt = token.hasClaim(TokenClaims.XSUAA.ISSUED_AT)
                    ? Instant.ofEpochSecond(Long.parseLong(token.getClaims().get(TokenClaims.XSUAA.ISSUED_AT).toString()))
                    : null;
            return Mono.just(new Jwt(token.getTokenValue(), issuedAt,
                    token.getExpiration(), token.getHeaders(), token.getClaims()));
        }
        catch (NumberFormatException e){
            throw new BadJwtException("Error parsing JWT: " + e.getMessage(), e);
        }
    }
}
