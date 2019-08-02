package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.extractor.DefaultAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.extractor.LocalAuthoritiesExtractor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

/**
 * Encapsulates the {@link TokenAuthenticationConverter} that extracts authorization related
 * information from the Jwt token. For example
 * the{@link LocalAuthoritiesExtractor} can remove the ugly application id
 * prefix (e.g.my-application-demo!t1229) from the scopes in the JWT.
 */
public class ReactiveTokenAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {
	TokenAuthenticationConverter converter;

	public ReactiveTokenAuthenticationConverter(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		this.converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration.getAppId());
	}

	/**
	 * This method allows to overwrite the default behavior of the
	 * {@link Token#getAuthorities()} implementation.
	 */
	public ReactiveTokenAuthenticationConverter setLocalScopeAsAuthorities(boolean extractLocalScopesOnly) {
		this.converter.setLocalScopeAsAuthorities(extractLocalScopesOnly);
		return this;
	}

	@Override
	public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
		return Mono.just(converter.convert(jwt));
	}

}
