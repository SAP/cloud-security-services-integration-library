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
package testservice.api.multipleBindings;

import com.sap.cloud.security.xsuaa.XsuaaCredentials;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationCustom;
import com.sap.cloud.security.xsuaa.extractor.LocalAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaAudienceValidator;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@EnableWebSecurity
@Profile({ "test.api.multiple" })
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.authorizeRequests()
				.antMatchers("/**").hasAuthority("Display")
				.anyRequest().denyAll()
			.and().oauth2ResourceServer()
			.jwt()
				.jwtAuthenticationConverter(getJwtAuthenticationConverter());
		// @formatter:on
	}

	@Bean
	@ConfigurationProperties("vcap.services.<<name of your xsuaa instance of plan application>>.credentials")
	public XsuaaCredentials xsuaaCredentials() {
		return new XsuaaCredentials(); // primary Xsuaa service binding, e.g. application
	}

	@Bean
	public XsuaaServiceConfiguration customXsuaaConfig() {
		return new XsuaaServiceConfigurationCustom(xsuaaCredentials());
	}

	@Bean
	@ConfigurationProperties("vcap.services.<<name of your xsuaa instance of plan broker>>.credentials")
	public XsuaaCredentials brokerCredentials() {
		return new XsuaaCredentials(); // secondary Xsuaa service binding, e.g. broker
	}

	@Bean
	public JwtDecoder getJwtDecoder() {
		XsuaaCredentials brokerXsuaaCredentials = brokerCredentials();

		XsuaaAudienceValidator customAudienceValidator = new XsuaaAudienceValidator(customXsuaaConfig());
		// customAudienceValidator.configureAnotherXsuaaInstance("test3!b1", "sb-clone1!b22|test3!b1");
		customAudienceValidator.configureAnotherXsuaaInstance(brokerXsuaaCredentials.getXsAppName(), brokerXsuaaCredentials.getClientId());
		return new XsuaaJwtDecoderBuilder(customXsuaaConfig()).withTokenValidators(customAudienceValidator).build();
	}

	Converter<Jwt, AbstractAuthenticationToken> getJwtAuthenticationConverter() {
		LocalAuthoritiesExtractor extractor = new LocalAuthoritiesExtractor(xsuaaCredentials().getXsAppName(), brokerCredentials().getXsAppName());
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(extractor);
		return converter;
	}
}
