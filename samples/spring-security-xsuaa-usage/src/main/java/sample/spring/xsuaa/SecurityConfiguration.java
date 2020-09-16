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
import com.sap.cloud.security.xsuaa.token.Token;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaAudienceValidator;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Configuration
@EnableWebSecurity(debug = true) // TODO "debug" may include sensitive information. Do not use in a production system!
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session is created by approuter
			.and()
				.authorizeRequests()
				.antMatchers("/v1/sayHello").hasAuthority("Read")
				.antMatchers("/v1/*").authenticated()
				.antMatchers("/v2/*").hasAuthority("Read")
				.antMatchers("/v3/*").hasAuthority("Read")
				.antMatchers("/v3/requestRefreshToken/*").hasAuthority("Read")
				.anyRequest().denyAll()
			.and()
				.oauth2ResourceServer()
				.jwt()
				.jwtAuthenticationConverter(getJwtAuthenticationConverter());
		// @formatter:on
	}

	/**
	 * Customizes how GrantedAuthority are derived from a Jwt
	 */
	Converter<Jwt, AbstractAuthenticationToken> getJwtAuthenticationConverter() {
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration);
		converter.setLocalScopeAsAuthorities(true);
		return converter;
	}

	@Bean
	public JwtDecoder xsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		return new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration)
				.withoutXsuaaAudienceValidator()
				.withTokenValidators(new MyAudienceValidator(xsuaaServiceConfiguration))
				//.withRestOperations(xsuaaRestOperations)
				.build();
	}

	private class MyAudienceValidator extends XsuaaAudienceValidator {
		XsuaaServiceConfiguration configuration;

		public MyAudienceValidator(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
			super(xsuaaServiceConfiguration);
			this.configuration = xsuaaServiceConfiguration;
		}

		@Override
		public OAuth2TokenValidatorResult validate(Jwt token) {
			if(isClone(token)) {
				String description = String.format("Clone token with client id %s is rejected.", ((Token) token).getClientId());
				return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, description, null));
			}
			return super.validate(token);
		}

		private boolean isClone(Jwt token) {
			if(token instanceof Token) {
				// workarount till 2.7.8
				// return ((Token) token).isClone(configuration.getAppId());
				return configuration.getAppId().contains("!b") && ((Token)token).getClientId().endsWith("|" + configuration.getAppId());
			}
			return false;
		}
	}

}
