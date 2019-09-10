package com.sap.cloud.security.xsuaa.extractor;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

import com.sap.cloud.security.xsuaa.token.XsuaaToken;

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
