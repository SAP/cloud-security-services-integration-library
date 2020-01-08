package com.sap.cloud.security.token;

import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * This utility class translates XSUAA scopes that are specified in global form
 * to local ones.
 */
public class XsuaaScopeTranslator {
	private final Pattern globalScopePattern;

	public XsuaaScopeTranslator(String appId) {
		this.globalScopePattern = Pattern.compile(appId + "\\.(.+)");
	}

	public List<String> toLocalScope(Collection<String> scopes) {
		return scopes.stream()
				.map(this::convertToLocalScope)
				.collect(Collectors.toList());
	}

	private String convertToLocalScope(String scope) {
		Matcher matcher = globalScopePattern.matcher(scope);
		if (matcher.matches()) {
			return matcher.group(matcher.groupCount());
		}
		return scope;
	}

}
