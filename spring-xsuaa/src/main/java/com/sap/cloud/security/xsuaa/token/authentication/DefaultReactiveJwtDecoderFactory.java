package com.sap.cloud.security.xsuaa.token.authentication;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

public class DefaultReactiveJwtDecoderFactory implements ReactiveJwtDecoderFactory {

	@Override
	public ReactiveJwtDecoder create(String jku, OAuth2TokenValidator<Jwt> tokenValidator) {
		NimbusReactiveJwtDecoder decoder = new NimbusReactiveJwtDecoder(jku);
		decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(tokenValidator));
		return decoder;
	}
}
