/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.webflux.xsuaa;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.spring.config.IdentityServicesPropertySourceFactory;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.token.authentication.AuthenticationToken;
import com.sap.cloud.security.spring.token.authentication.JwtDecoderBuilder;
import com.sap.cloud.security.spring.token.ReactiveTokenAuthenticationConverter
//import com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory;
//import com.sap.cloud.security.xsuaa.token.ReactiveTokenAuthenticationConverter;
//import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import com.sap.cloud.security.spring.token.authentication.ReactiveHybridJwtDecoder;
import com.sap.cloud.security.token.TokenClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Configuration
@EnableWebSecurity
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, ignoreResourceNotFound = true, value = { "" }) // might be auto-configured in a future release
public class SecurityConfiguration {

	@Autowired
	Converter<Jwt, AbstractAuthenticationToken> authConverter;
	//Converter <Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> authConverter;

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;
	OAuth2ServiceConfiguration iasServiceConfiguration;

	/*@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
		http.authorizeExchange()
				.pathMatchers("/v1/sayHello").hasAuthority("Read")
				.and().oauth2ResourceServer().jwt()
				.jwtAuthenticationConverter(authConverter)
				.jwtDecoder(new JwtDecoderBuilder()
						.build());
		return http.build();
	}
	*/

	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
		http.authorizeExchange()
				.pathMatchers("/v1/sayHello").hasAuthority("Read")
				.and().oauth2ResourceServer().jwt()
				.jwtAuthenticationConverter(jwt -> new MyCustomHybridTokenAuthenticationConverter().convert(jwt))
				.jwtDecoder(new JwtDecoderBuilder()
						.withXsuaaServiceConfiguration(xsuaaServiceConfiguration)
						.withIasServiceConfiguration(iasServiceConfiguration)
						.buildAsReactive());
		return http.build();
	}

	//.withPostValidationActions(token -> logger.info("post validation action performed"))

	/**
	 * Customizes how GrantedAuthority are derived from a Jwt
	 */
	Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> getJwtAuthenticationConverter() {
		ReactiveTokenAuthenticationConverter converter = new ReactiveTokenAuthenticationConverter(xsuaaServiceConfiguration);
		converter.setLocalScopeAsAuthorities(true);
		return converter;
	}

	/**
	 * Workaround for hybrid use case until Cloud Authorization Service is globally available.
	 */
	class MyCustomHybridTokenAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

		public AbstractAuthenticationToken doConversion(Jwt jwt) {
			if (jwt.hasClaim(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE)) {
				return authConverter.convert(jwt);
			}
			return new AuthenticationToken(jwt, deriveAuthoritiesFromGroup(jwt));
		}


		private Collection<GrantedAuthority> deriveAuthoritiesFromGroup(Jwt jwt) {
			Collection<GrantedAuthority> groupAuthorities = new ArrayList<>();
			if (jwt.hasClaim(TokenClaims.GROUPS)) {
				List<String> groups = jwt.getClaimAsStringList(TokenClaims.GROUPS);
				for (String group : groups) {
					groupAuthorities.add(new SimpleGrantedAuthority(group.replace("IASAUTHZ_", "")));
				}
			}
			return groupAuthorities;
		}

		public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
			return Mono.just(jwt).map(this::doConversion);
		}
	}

}
