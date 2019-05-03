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
package testservice.api.nohttp;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.mock.MockXsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Profile({ "test.api.nohttp" })
@Configuration
public class SecurityConfiguration {

	@Bean
	XsuaaServiceConfiguration getXsuaaServiceConfiguration() {
		return new MockXsuaaServiceConfiguration();
	}

	@Bean
	JwtDecoder jwtDecoder() {
		return new XsuaaJwtDecoderBuilder(getXsuaaServiceConfiguration()).build();
	}

	Converter<Jwt, AbstractAuthenticationToken> getJwtAuthenticationConverter() {
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(getXsuaaServiceConfiguration());
		converter.setLocalScopeAsAuthorities(true);
		return converter;
	}

}
