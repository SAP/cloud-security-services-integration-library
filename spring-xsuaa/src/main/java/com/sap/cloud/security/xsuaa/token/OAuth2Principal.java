/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.Collection;
import java.util.Map;

class OAuth2Principal extends XsuaaToken implements OAuth2AuthenticatedPrincipal {

	private final Collection<GrantedAuthority> authorities;
	private final Map<String, Object> attributes;
	private final String name;

	public OAuth2Principal(AuthenticationToken authenticationToken) {
		super(authenticationToken.getToken());
		this.authorities = authenticationToken.getAuthorities();
		this.name = authenticationToken.getName();
		this.attributes = authenticationToken.getTokenAttributes();
	}

	@Override
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String getName() {
		return this.name;
	}
}
