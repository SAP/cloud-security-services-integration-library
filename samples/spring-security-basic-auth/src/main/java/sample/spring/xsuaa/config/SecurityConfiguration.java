/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa.config;

import com.sap.cloud.security.spring.config.IdentityServicesPropertySourceFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import sample.spring.xsuaa.security.TokenBrokerResolver;

@Configuration
@EnableWebSecurity
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, ignoreResourceNotFound = true, value = { "" })
public class SecurityConfiguration {
	@Autowired
	Converter<Jwt, AbstractAuthenticationToken> authConverter;
	@Autowired
	TokenBrokerResolver tokenBrokerResolver;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		//enforce browser login popup with basic authentication
		BasicAuthenticationEntryPoint authEntryPoint = new BasicAuthenticationEntryPoint();
		authEntryPoint.setRealmName("spring-security-basic-auth");

		// @formatter:off
		http.authorizeHttpRequests()
				.requestMatchers("/mirror-token").hasAuthority("Display")
				.requestMatchers("/health").permitAll()
				.anyRequest().denyAll()
			.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
				.exceptionHandling()
				.authenticationEntryPoint(authEntryPoint)
			.and()
				.oauth2ResourceServer()
				.bearerTokenResolver(tokenBrokerResolver)
				.jwt()
				.jwtAuthenticationConverter(authConverter);
		// @formatter:on

		return http.build();
	}
}
