package com.sap.cloud.security.token;

import com.sap.cloud.security.xsuaa.Assertions;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * This utility class translates XSUAA scopes that are specified in global form
 * and prefixed with the "appId.", to local ones.
 */
public class XsuaaScopeConverter implements ScopeConverter {
	private final Pattern globalScopePattern;

	/**
	 * Creates an instance of the converter.
	 * 
	 * @param appId
	 *            the xs application name e.g. myapp!t123.
	 */
	public XsuaaScopeConverter(String appId) {
		Assertions.assertHasText(appId, "appId must not be null or empty.");
		this.globalScopePattern = Pattern.compile(appId + "\\.(.+)");
	}

	@Override
	public List<String> convert(Collection<String> scopes) {
		return scopes.stream()
				.map(this::convertToLocalScope)
				.filter(Objects::nonNull)
				.collect(Collectors.toList());
	}

	private String convertToLocalScope(String scope) {
		Matcher matcher = globalScopePattern.matcher(scope);
		if (matcher.matches()) {
			return matcher.group(matcher.groupCount());
		}
		return null;
	}

}
