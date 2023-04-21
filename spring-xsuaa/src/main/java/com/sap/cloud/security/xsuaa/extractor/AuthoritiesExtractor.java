/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.xsuaa.token.XsuaaToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Extracts the authorities from the Jwt token. Can use this method to map /
 * manipulate scopes, e.g. by changing their prefix, etc.
 */
public interface AuthoritiesExtractor {
	/**
	 * Returns the granted authorities based on the information in the Jwt. A
	 * standard implementation will base the granted authorities on the scopes.
	 *
	 * @param jwt
	 *            the Jwt to extract the authorities from.
	 * @return the collection of granted authorities.
	 */
	Collection<GrantedAuthority> getAuthorities(XsuaaToken jwt);
}
