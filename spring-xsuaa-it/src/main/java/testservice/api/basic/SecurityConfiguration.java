/*
 * Copyright 2002-2018 the original author or authors.
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
package testservice.api.basic;

import java.net.MalformedURLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.extractor.AuthenticationMethod;
import com.sap.cloud.security.xsuaa.extractor.TokenBrokerResolver;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;

@Profile({ "test.api.basic" })
@EnableWebSecurity
@EnableCaching
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	public static TokenBrokerResolver tokenBrokerResolver; //make static for tests
	@Value("${mockxsuaaserver.url}")
	String mockServerUrl;

	
	@Autowired
	CacheManager cacheManager;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		tokenBrokerResolver =  new TokenBrokerResolver(getXsuaaServiceConfiguration(), cacheManager.getCache("token"),
				AuthenticationMethod.BASIC);
		// @formatter:off
		http.authorizeRequests().antMatchers("/message/**").hasAuthority("SCOPE_openid").anyRequest().authenticated()
				.and().oauth2ResourceServer()
				.bearerTokenResolver(tokenBrokerResolver)
				.jwt().jwtAuthenticationConverter(new TokenAuthenticationConverter(getXsuaaServiceConfiguration()));
		// @formatter:on
	}

	@Bean
	XsuaaServiceConfiguration getXsuaaServiceConfiguration() throws MalformedURLException {
		return new MockXsuaaServiceConfiguration(mockServerUrl, "java-hello-world");
	}

	@Bean
	JwtDecoder jwtDecoder() throws MalformedURLException {
		return new XsuaaJwtDecoderBuilder(getXsuaaServiceConfiguration()).build();
	}
}
