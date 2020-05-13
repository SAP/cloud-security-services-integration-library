package com.sap.cloud.security.xsuaa.extractor;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.sap.cloud.security.xsuaa.token.XsuaaToken;

public class LocalAuthoritiesExtractor implements AuthoritiesExtractor {

	protected Set<String> appIds = new HashSet<>();

	public LocalAuthoritiesExtractor(String... appIds) {
		Collections.addAll(this.appIds, appIds);
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities(XsuaaToken jwt) {
		Set<String> scopeAuthorities = new HashSet<>();

		appIds.stream().forEach((appId) -> {
			scopeAuthorities.addAll(getScopes(jwt, appId));
		});

		Stream<String> authorities = Stream.of(scopeAuthorities).flatMap(Collection::stream);

		return authorities.map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	}

	protected Set<String> getScopes(XsuaaToken jwt, String appId) {
		Collection<String> scopes = jwt.getScopes();
		if (scopes == null) {
			return Collections.emptySet();
		}
		return scopes.stream()
				.filter(scope -> scope.startsWith(appId + "."))
				.map(scope -> scope.replaceFirst(appId + ".", ""))
				.collect(Collectors.toSet());

	}

}
