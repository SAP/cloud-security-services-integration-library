package com.sap.cloud.security.token;

import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * This utility class translates scopes that are specified in global form
 * to local ones.
 */
public class ScopeTranslator {

	private static final Pattern GLOBAL_SCOPE_PATTERN = Pattern.compile("[\\w-\\.]+!\\w+\\.(.+)");

	public List<String> translateToLocalScope(Collection<String> scopes) {
		return scopes.stream()
				.map(this::convertToLocalScope)
				.collect(Collectors.toList());
	}

	private String convertToLocalScope(String scope) {
		Matcher matcher = GLOBAL_SCOPE_PATTERN.matcher(scope);
		if (matcher.matches()) {
			return matcher.group(matcher.groupCount());
		}
		return scope;
 	}

}
