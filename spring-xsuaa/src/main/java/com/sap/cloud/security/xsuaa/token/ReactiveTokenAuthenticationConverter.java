/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.extractor.LocalAuthoritiesExtractor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

/**
 * Encapsulates the {@link TokenAuthenticationConverter} that extracts
 * authorization related information from the Jwt token. For example
 * the{@link LocalAuthoritiesExtractor} can remove the ugly application id
 * prefix (e.g.my-application-demo!t1229) from the scopes in the JWT.
 */
public class ReactiveTokenAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {
	final TokenAuthenticationConverter converter;

	public ReactiveTokenAuthenticationConverter(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		this.converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration.getAppId());
	}

	/**
	 * This method allows to overwrite the default behavior of the
	 * {@link Token#getAuthorities()} implementation.
	 *
	 * @param extractLocalScopesOnly
	 *            * true when {@link Token#getAuthorities()} should only extract
	 *            local * scopes. Local scopes means that non-application specific
	 *            scopes * are filtered out and scopes are returned without appId
	 *            prefix, * e.g. "Display". Creates a new converter with a new *
	 *            {@link LocalAuthoritiesExtractor}
	 * @return the token authenticator itself
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
