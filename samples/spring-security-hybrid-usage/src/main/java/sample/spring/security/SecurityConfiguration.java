/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.spring.security;

import com.sap.cloud.security.token.authentication.AuthenticationToken;
import com.sap.cloud.security.token.TokenClaims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Configuration
@EnableWebSecurity(debug = true) // TODO "debug" may include sensitive information. Do not use in a production system!
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	Converter<Jwt, AbstractAuthenticationToken> authConverter;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
				.authorizeRequests()
				.antMatchers("/sayHello").hasAuthority("Read")
				.antMatchers("/*").authenticated()
				.anyRequest().denyAll()
			.and()
				.oauth2ResourceServer()
				.jwt()
				.jwtAuthenticationConverter(new MyCustomTokenAuthenticationConverter());
		// @formatter:on
	}

	/**
	 * Workaround until Cloud Authorization Service is globally available.
	 */
	class MyCustomTokenAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

		public AbstractAuthenticationToken convert(Jwt jwt) {
			if(jwt.containsClaim(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE)) {
				return authConverter.convert(jwt);
			}
			return new AuthenticationToken(jwt, deriveAuthoritiesFromGroup(jwt));
		}

		private Collection<GrantedAuthority> deriveAuthoritiesFromGroup(Jwt jwt) {
			Collection<GrantedAuthority> groupAuthorities = new ArrayList<>();
			if (jwt.containsClaim(TokenClaims.GROUPS)) {
				List<String> groups = jwt.getClaimAsStringList(TokenClaims.GROUPS);
				for (String group: groups) {
					groupAuthorities.add(new SimpleGrantedAuthority(group.replace("IASAUTHZ_", "")));
				}
			}
			return groupAuthorities;
		}
	}
}
