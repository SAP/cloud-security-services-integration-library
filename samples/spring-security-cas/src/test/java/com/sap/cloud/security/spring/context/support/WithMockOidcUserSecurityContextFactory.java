/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.sap.cloud.security.spring.context.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.*;

/**
 * TODO: extract as library or contribute to spring security test
 */

/**
 * Initializes the Spring Security Context with a OAuth2AuthenticationToken instance, which comes with
 * an encoded oidc token with some default claims but without header and signature.
 *
 * @author Nena Raab
 * @see WithMockOidcUser
 */
final class WithMockOidcUserSecurityContextFactory implements
		WithSecurityContextFactory<WithMockOidcUser> {

	//TODO skip if adc server is not running

	public SecurityContext createSecurityContext(WithMockOidcUser withUser) {
		String userName = StringUtils.hasLength(withUser.username()) ? withUser
				.username() : withUser.value();
		if (userName == null) {
			throw new IllegalArgumentException(withUser
					+ " cannot have null username on both username and value properties");
		}

		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		for (String authority : withUser.authorities()) {
			grantedAuthorities.add(new SimpleGrantedAuthority(authority));
		}

		if (grantedAuthorities.isEmpty()) {
			for (String role : withUser.roles()) {
				if (role.startsWith("ROLE_")) {
					throw new IllegalArgumentException("roles cannot start with ROLE_ Got "
							+ role);
				}
				grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role));
			}
		}

		OidcUser principal = new DefaultOidcUser(grantedAuthorities,
				new OidcIdTokenFactory(userName, withUser.clientId()).build(),
				"attributes");
		Authentication authentication = new OAuth2AuthenticationToken(
				principal, principal.getAuthorities(), withUser.clientId());

		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		return context;
	}

	private class OidcIdTokenFactory {
		private Map<String, Object> claims = new HashMap<>();
		final Instant expiredAt = new GregorianCalendar().toInstant().plusSeconds(600);
		final Instant issuedAt = new GregorianCalendar().toInstant().minusSeconds(3);

		public OidcIdTokenFactory(String userName, String clientId) {
			claims.put  ("client_id", clientId); // mandatory
			claims.put("iat", issuedAt.getEpochSecond());
			claims.put("exp", expiredAt.getEpochSecond());
			claims.put("attributes", "value"); // mandatory TODO understand purpose
			claims.put("given_name", userName); // TODO understand how to configure unique name
			claims.put("email", userName + "@test.org");
		}

		public OidcIdToken build() {
			return new OidcIdToken(getToken(), issuedAt, expiredAt, claims);
		}

		private String getToken() {
			ObjectMapper mapper = new ObjectMapper();
			ObjectNode root = mapper.createObjectNode();
			String jwtToken = root.toString();
			return base64Encode(jwtToken.getBytes());
		}

		private String base64Encode(byte[] bytes) {
			return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
		}
	}
}
