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

import com.sap.cloud.security.authentication.JwtDecoderBuilder;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationImpl;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import com.sap.cloud.security.xsuaa.token.XsuaaTokenAuthenticationConverter;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Configuration
@EnableWebSecurity(debug = true) // TODO "debug" may include sensitive information. Do not use in a production system!
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
				.authorizeRequests()
				.antMatchers("/v1/sayHello").access("hasAuthority('Read') or hasRole('GROUP_READ')")
				.antMatchers("/v1/*").authenticated()
				.antMatchers("/v2/*").access("hasAuthority('Read') or hasRole('GROUP_READ')")
				.anyRequest().denyAll()
			.and()
				.oauth2ResourceServer()
				.jwt()
				.decoder(hybridJwtDecoder())
				.jwtAuthenticationConverter(new XsuaaTokenAuthenticationConverter(getXsuaaAppId()));
		// @formatter:on
	}

	String getXsuaaAppId() {
		return xsuaaConfiguration().getProperty(CFConstants.XSUAA.APP_ID);
	}

	JwtDecoder hybridJwtDecoder() {
		return new JwtDecoderBuilder(xsuaaConfiguration(), iasConfiguration().getClientId()).buildHybrid();
	}

	@Bean
	@ConfigurationProperties("vcap.services.xsuaa-authentication.credentials")
	public OAuth2ServiceConfiguration xsuaaConfiguration() {
		return new OAuth2ServiceConfigurationImpl(Service.XSUAA);
	}

	@Bean
	@ConfigurationProperties("vcap.services.ias-authentication.credentials")
	public OAuth2ServiceConfiguration iasConfiguration() {
		return new OAuth2ServiceConfigurationImpl(Service.IAS);
	}
}
