/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package testservice.api.basic;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.extractor.DefaultAuthenticationInformationExtractor;
import com.sap.cloud.security.xsuaa.extractor.TokenBrokerResolver;
import com.sap.cloud.security.xsuaa.mock.MockXsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;

@EnableWebSecurity
@EnableCaching
@Profile({ "test.api.basic" })
@java.lang.SuppressWarnings("squid:S2696")
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	public static TokenBrokerResolver tokenBrokerResolver; // make static for tests

	@Autowired
	CacheManager cacheManager;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		tokenBrokerResolver = new TokenBrokerResolver(getXsuaaServiceConfiguration(), cacheManager.getCache("token"),
				null, new DefaultAuthenticationInformationExtractor());
		// @formatter:off
		http.authorizeRequests()
				.antMatchers("/user/**").hasAuthority("java-hello-world.Display")
				.anyRequest().denyAll()
				.and().oauth2ResourceServer()
				.bearerTokenResolver(tokenBrokerResolver)
				.jwt().jwtAuthenticationConverter(getJwtAuthenticationConverter());
		// @formatter:on
	}

	Converter<Jwt, AbstractAuthenticationToken> getJwtAuthenticationConverter() {
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(getXsuaaServiceConfiguration());
		return converter;
	}

	@Bean
	public JwtDecoder xsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		return new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration).build();
	}

	@Bean
	XsuaaServiceConfiguration getXsuaaServiceConfiguration() {
		return new MySecurityConfiguration();
	}

	private class MySecurityConfiguration extends MockXsuaaServiceConfiguration {

		@Override
		public String getClientSecret() {
			return "mysecret-basic";
		}

	}
}
