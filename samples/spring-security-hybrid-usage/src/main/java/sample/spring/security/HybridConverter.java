/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.security;

import com.sap.cloud.security.spring.token.authentication.AuthenticationToken;
import com.sap.cloud.security.token.TokenClaims;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class HybridConverter implements Converter<Jwt, AbstractAuthenticationToken> {


	private final Converter<Jwt, AbstractAuthenticationToken> authConverter;

	public HybridConverter(Converter<Jwt, AbstractAuthenticationToken> jwtGrantedAuthoritiesConverter) {
		this.authConverter = jwtGrantedAuthoritiesConverter;
	}
	@Override
	public AbstractAuthenticationToken convert(Jwt jwt) {
		if (jwt.hasClaim(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE)) {
			return authConverter.convert(jwt);
		}
		return new AuthenticationToken(jwt, deriveAuthoritiesFromGroup(jwt));
	}

	private Collection<GrantedAuthority> deriveAuthoritiesFromGroup(Jwt jwt) {
		Collection<GrantedAuthority> groupAuthorities = new ArrayList<>();
		if (jwt.hasClaim(TokenClaims.GROUPS)) {
			List<String> groups = jwt.getClaimAsStringList(TokenClaims.GROUPS);
			for (String group : groups) {
				groupAuthorities.add(new SimpleGrantedAuthority(group.replace("IASAUTHZ_", "")));
			}
		}
		return groupAuthorities;
	}
}