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

import com.sap.cloud.security.token.authentication.JwtDecoderBuilder;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationProperties;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.servlet.AuthenticationToken;
import com.sap.cloud.security.token.TokenClaims;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import com.sap.cloud.security.token.xsuaa.XsuaaTokenAuthenticationConverter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

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
				.antMatchers("/sayHello").access("hasAuthority('Read') or hasAuthority('GROUP_READ')") //hasRole and overwrite defaultRolePrefix
				.antMatchers("/*").authenticated()
				.anyRequest().denyAll()
			.and()
				.oauth2ResourceServer()
				.jwt()
				.decoder(hybridJwtDecoder())
				.jwtAuthenticationConverter(new MyCustomTokenAuthenticationConverter(getXsuaaAppId()));
		// @formatter:on
	}

	JwtDecoder hybridJwtDecoder() {
		return new JwtDecoderBuilder()
				.withIasServiceConfiguration(iasConfiguration())
				.withXsuaaServiceConfiguration(xsuaaConfiguration())
				.buildHybrid();
	}

	@Bean
	@ConfigurationProperties("xsuaa")
	public OAuth2ServiceConfiguration xsuaaConfiguration() {
		return new OAuth2ServiceConfigurationProperties(Service.XSUAA);
	}

	@Bean
	@ConfigurationProperties("identity")
	public OAuth2ServiceConfiguration iasConfiguration() {
		return new OAuth2ServiceConfigurationProperties(Service.IAS);
	}

	String getXsuaaAppId() {
		return xsuaaConfiguration().getProperty(CFConstants.XSUAA.APP_ID);
	}

	private static class MyCustomTokenAuthenticationConverter extends XsuaaTokenAuthenticationConverter {
		/**
		 * @param appId the xsuaa application identifier
		 *              e.g. myXsAppname!t123
		 */
		public MyCustomTokenAuthenticationConverter(String appId) {
			super(appId);
		}

		@Override
		public AbstractAuthenticationToken convert(Jwt jwt) {
			Collection<GrantedAuthority> derivedAuthorities;

			if(jwt.containsClaim(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE)) {
				derivedAuthorities = localScopeAuthorities(jwt);
			} else {
				derivedAuthorities = deriveAuthoritiesFromGroup(jwt);
			}
			return new AuthenticationToken(jwt, derivedAuthorities);
		}

		private Collection<GrantedAuthority> deriveAuthoritiesFromGroup(Jwt jwt) {
			Collection<GrantedAuthority> groupAuthorities = new ArrayList<>();
			if (jwt.containsClaim(TokenClaims.GROUPS)) {
				List<String> groups = jwt.getClaimAsStringList(TokenClaims.GROUPS);
				for (String group: groups) {
					groupAuthorities.add(new SimpleGrantedAuthority("GROUP_" + group));
				}
			}
			return groupAuthorities;
		}
	}
}
