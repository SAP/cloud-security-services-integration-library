package com.sap.cloud.security.token;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * This utility class translates XSUAA scopes that are specified in global form
 * and prefixed with the "appId.", to local ones.
 */
public class XsuaaScopeConverter implements TokenScopeConverter {
	private final Pattern globalScopePattern;

	/**
	 * Creates an instance of the converter.
	 * @param appId the xs application name e.g. myapp!t123.
	 */
	public XsuaaScopeConverter(String appId) {
		this.globalScopePattern = Pattern.compile(appId + "\\.(.+)");
	}

	@Override
	public List<String> convert(List<String> scopes) {
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
