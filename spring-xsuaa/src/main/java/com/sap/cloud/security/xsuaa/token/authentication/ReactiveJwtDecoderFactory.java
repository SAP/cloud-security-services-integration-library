package com.sap.cloud.security.xsuaa.token.authentication;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

public interface ReactiveJwtDecoderFactory {
	ReactiveJwtDecoder create(String jku, OAuth2TokenValidator<Jwt> tokenValidator);
}
