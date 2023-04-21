/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity(debug = true) // TODO "debug" may include sensitive information. Do not use in a production system!
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class SecurityConfiguration {

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session is created by approuter
				.and()
				.authorizeHttpRequests(authz ->
						authz.requestMatchers("/v1/sayHello").hasAuthority("Read")
								.requestMatchers("/v1/*").authenticated()
								.requestMatchers("/v2/*").hasAuthority("Read")
								.requestMatchers("/v3/*").hasAuthority("Read")
								.requestMatchers("/v3/requestRefreshToken/*").hasAuthority("Read")
								.requestMatchers("/health").permitAll()
								.anyRequest().denyAll()
				)
				.oauth2ResourceServer()
				.jwt()
				.jwtAuthenticationConverter(getJwtAuthenticationConverter());
		// @formatter:on

		return http.build();
	}

	/**
	 * Customizes how GrantedAuthority are derived from a Jwt
	 */
	Converter<Jwt, AbstractAuthenticationToken> getJwtAuthenticationConverter() {
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration);
		converter.setLocalScopeAsAuthorities(true);
		return converter;
	}

}
