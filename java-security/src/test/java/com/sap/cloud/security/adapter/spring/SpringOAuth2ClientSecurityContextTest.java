/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.io.IOException;
import java.time.Instant;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.token.TokenClaims.SUBJECT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singleton;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SpringOAuth2ClientSecurityContextTest {
	SapIdToken sapIdToken;

	@BeforeEach
	public void setUp() throws IOException {
		sapIdToken = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
		SpringSecurityContext.clear();
	}

	@Test
	public void getTokenReturnsIasOidcToken() {
		setToken(sapIdToken);
		assertThat(SpringSecurityContext.getToken().getService()).isEqualTo(IAS);
		assertThat(SpringSecurityContext.getToken().getClaimAsString(SUBJECT)).isEqualTo("P176945");
	}

	@Test
	public void clear_removesToken() {
		setToken(sapIdToken);
		SpringSecurityContext.clear();

		assertThat(SpringSecurityContext.getToken()).isNull();
	}

	private static void setToken(Token token) {
		OidcIdToken oidcIdToken = new OidcIdToken(token.getTokenValue(), Instant.now(), Instant.now().plusSeconds(1L),
				token.getClaims());
		SecurityContextHolder.getContext().setAuthentication(getMockAuthentication(oidcIdToken));
	}

	static Authentication getMockAuthentication(OidcIdToken oidcIdToken) {
		Authentication authentication = mock(Authentication.class);
		when(authentication.getPrincipal())
				.thenReturn(new DefaultOidcUser(singleton(new SimpleGrantedAuthority("openid")), oidcIdToken));
		when(authentication.isAuthenticated()).thenReturn(true);
		return authentication;
	}
}
