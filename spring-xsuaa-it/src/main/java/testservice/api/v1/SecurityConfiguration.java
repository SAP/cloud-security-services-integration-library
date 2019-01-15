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
package testservice.api.v1;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;

@Profile({ "test.api.v1" })
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	@Value("${mockxsuaaserver.url}")
	String mockServerUrl;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.authorizeRequests().
			antMatchers("/message/**").
			hasAuthority("SCOPE_openid").
			anyRequest().
			authenticated().and().oauth2ResourceServer().
			jwt()
				.jwtAuthenticationConverter(new TokenAuthenticationConverter(getXsuaaServiceConfiguration()));
		// @formatter:on
	}

	@Bean
	XsuaaServiceConfiguration getXsuaaServiceConfiguration()
	{
		return new MockXsuaaServiceConfiguration(mockServerUrl,"java-hello-world");
	}

	@Bean
	JwtDecoder jwtDecoder() {	
		return new XsuaaJwtDecoderBuilder(getXsuaaServiceConfiguration()).build();
	}


}
