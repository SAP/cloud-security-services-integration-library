package com.sap.cloud.security.xsuaa.extractor;

import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.sap.cloud.security.xsuaa.token.TokenImpl;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class LocalAuthoritiesExtractor implements AuthoritiesExtractor {

	protected String appId;

	public LocalAuthoritiesExtractor(String appId) {
		this.appId = appId;
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities(TokenImpl jwt) {
		Collection<String> scopeAuthorities = getScopes(jwt);

		Stream<String> authorities = Stream.of(scopeAuthorities).flatMap(Collection::stream);

		return authorities.map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	}

	protected Collection<String> getScopes(TokenImpl jwt) {
		Collection<String> scopes = jwt.getScopes();
		if (scopes == null) {
			return Collections.emptyList();
		}
		return scopes.stream()
				.filter(scope -> scope.startsWith(appId + "."))
				.map(scope -> scope.replaceFirst(appId + ".", ""))
				.collect(Collectors.toList());

	}

}
