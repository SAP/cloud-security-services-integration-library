/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.Token;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;

import static com.sap.cloud.security.config.Service.IAS;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class AuthenticationTokenTest {

	JwtGenerator jwtGenerator = JwtGenerator.getInstance(IAS, "theClientId");

	Collection<GrantedAuthority> singleAuthority = Collections.singletonList(new SimpleGrantedAuthority("read"));

	@Test
	void equals() {
		Jwt jwt1 = Mockito.mock(Jwt.class);
		when(jwt1.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

		Jwt jwt2 = Mockito.mock(Jwt.class);
		when(jwt2.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

		AuthenticationToken cut = new AuthenticationToken(jwt1, null);

		assertEquals(cut, new AuthenticationToken(jwt1, null));
		assertEquals(cut, new AuthenticationToken(jwt2, null));
		assertEquals(new AuthenticationToken(jwt1, singleAuthority), new AuthenticationToken(jwt2, singleAuthority));

		assertEquals(cut.hashCode(), cut.hashCode());
		assertEquals(cut, new AuthenticationToken(jwt1, null));
	}

	@Test
	void notEquals() {
		Jwt jwt1 = Mockito.mock(Jwt.class);
		when(jwt1.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

		Jwt jwt2 = Mockito.mock(Jwt.class);
		jwtGenerator.withClaimValue("ext", "value");
		when(jwt2.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

		AuthenticationToken cut = new AuthenticationToken(jwt1, null);
		assertNotEquals(cut, new AuthenticationToken(jwt2, null));
		assertNotEquals(null, cut);
		assertNotEquals(cut, Mockito.mock(Jwt.class));
		assertNotEquals(cut, new AuthenticationToken(jwt1, singleAuthority));

		assertNotEquals(cut, new AuthenticationToken(jwt2, null));
	}

	@Test
	void getPrincipal() {
		Jwt jwt = Mockito.mock(Jwt.class);
		when(jwt.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());
		Object principal = new AuthenticationToken(jwt, null).getPrincipal();
		assertTrue(principal instanceof Token);
		assertEquals("theClientId", ((Token) principal).getClientId());
	}

	@Test
	void getName() {
		Jwt jwt = Mockito.mock(Jwt.class);
		when(jwt.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());
		assertEquals("the-user-id", new AuthenticationToken(jwt, null).getName());
	}
}
