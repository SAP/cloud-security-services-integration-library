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
package sample.spring.xsuaa;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.extractor.AuthenticationMethod;
import com.sap.cloud.security.xsuaa.extractor.TokenBrokerResolver;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;

@EnableWebSecurity
@EnableCaching
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Autowired
	CacheManager cacheManager;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		TokenBrokerResolver tokenBrokerResolver = new TokenBrokerResolver(xsuaaServiceConfiguration, cacheManager.getCache("token"), AuthenticationMethod.BASIC);

		// @formatter:off
		http.authorizeRequests()
				.antMatchers("/hello-token").hasAuthority("openid")
				.anyRequest().authenticated()
			.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
				.oauth2ResourceServer()
				.bearerTokenResolver(tokenBrokerResolver)
				.jwt()
				.jwtAuthenticationConverter(jwtAuthenticationConverter());
		// @formatter:on
	}

	@Bean
	Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration);
//		converter.setLocalScopeAsAuthorities(true);
		return converter;
	}

}
