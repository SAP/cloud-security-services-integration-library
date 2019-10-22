package com.sap.cloud.security.xsuaa.token.authentication;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;

public class DefaultJwtDecoderFactory implements JwtDecoderFactory {

	@Override
	public JwtDecoder create(String jku, OAuth2TokenValidator<Jwt> tokenValidator) {
		NimbusJwtDecoderJwkSupport decoder = new NimbusJwtDecoderJwkSupport(jku);
		decoder.setJwtValidator(tokenValidator);
		return decoder;
	}
}
