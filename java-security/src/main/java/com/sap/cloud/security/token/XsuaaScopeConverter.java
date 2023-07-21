/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.xsuaa.Assertions;

import java.io.Serial;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This utility class translates XSUAA scopes that are specified in global form
 * and prefixed with the "appId.", to local ones.
 */
public class XsuaaScopeConverter implements ScopeConverter {

	@Serial
	private static final long serialVersionUID = 2204172290850251807L;

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
	public Set<String> convert(Collection<String> scopes) {
		Set<String> convertedScopes = new LinkedHashSet<>();
		for (String scope : scopes) {
			String convertedScope = convertToLocalScope(scope);
			if (convertedScope != null) {
				convertedScopes.add(convertedScope);
			}
		}
		return convertedScopes;
	}

	private String convertToLocalScope(String scope) {
		Matcher matcher = globalScopePattern.matcher(scope);
		if (matcher.matches()) {
			return matcher.group(matcher.groupCount());
		}
		return null;
	}

}
