/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.webflux.hybrid;

import com.sap.cloud.security.spring.config.IdentityServiceConfiguration;
import com.sap.cloud.security.spring.config.IdentityServicesPropertySourceFactory;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.token.authentication.AuthenticationToken;
import com.sap.cloud.security.spring.token.authentication.JwtDecoderBuilder;
import com.sap.cloud.security.token.TokenClaims;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

@Configuration
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, ignoreResourceNotFound = true, value = { "" })
// might be auto-configured in a future release
public class SecurityConfiguration {

	private static final Logger logger = LoggerFactory.getLogger(SecurityConfiguration.class);

	@Autowired
	Converter<Jwt, AbstractAuthenticationToken> authConverter;

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;
	@Autowired
	IdentityServiceConfiguration iasServiceConfiguration;

	NoOpServerSecurityContextRepository sessionConfig = NoOpServerSecurityContextRepository.getInstance();

	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
		http.authorizeExchange((exchanges) ->
						exchanges
								.pathMatchers("v1/sayHello").hasAuthority("Read"))
				.securityContextRepository(sessionConfig)
				.oauth2ResourceServer(oauth2 -> oauth2
						.jwt(jwt -> jwt.jwtAuthenticationConverter(jwt2 ->
										new MyCustomHybridTokenAuthenticationConverter().convert(jwt2))
								.jwtDecoder(new JwtDecoderBuilder()
										.withXsuaaServiceConfiguration(xsuaaServiceConfiguration)
										.withIasServiceConfiguration(iasServiceConfiguration)
										.buildAsReactive())));
		return http.build();
	}

	/**
	 * Workaround for hybrid use case until Cloud Authorization Service is globally available.
	 */
	class MyCustomHybridTokenAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

		public AbstractAuthenticationToken doConversion(Jwt jwt) {
			logger.info("=== doConversion called ===");
			logger.info("JWT Subject: {}", jwt.getSubject());
			logger.info("JWT Claims: {}", jwt.getClaims().keySet());

			if (jwt.hasClaim(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE)) {
				logger.info("XSUAA token detected, using authConverter");
				return authConverter.convert(jwt);
			}
			logger.info("IAS token detected, deriving authorities from groups");
			return new AuthenticationToken(jwt, deriveAuthoritiesFromGroup(jwt));
		}

		private Collection<GrantedAuthority> deriveAuthoritiesFromGroup(Jwt jwt) {
			Collection<GrantedAuthority> groupAuthorities = new ArrayList<>();
			logger.info("=== Deriving authorities from JWT ===");
			if (jwt.hasClaim(TokenClaims.GROUPS)) {
				Object groupsClaim = jwt.getClaim(TokenClaims.GROUPS);
				logger.info("Groups claim found. Type: {}, Value: {}", groupsClaim.getClass().getName(), groupsClaim);
				List<String> groups = new ArrayList<>();

				// Handle both String and List<String>
				if (groupsClaim instanceof String) {
					logger.info("Groups claim is a String");
					groups.add((String) groupsClaim);
				} else if (groupsClaim instanceof List) {
					logger.info("Groups claim is a List");
					groups = jwt.getClaimAsStringList(TokenClaims.GROUPS);
				}

				logger.info("Processing {} group(s)", groups.size());
				for (String group : groups) {
					String authority = group.replace("IASAUTHZ_", "");
					logger.info("Group: '{}' -> Authority: '{}'", group, authority);
					groupAuthorities.add(new SimpleGrantedAuthority(authority));
				}
			} else {
				logger.warn("No groups claim found in JWT");
			}
			logger.info("Total authorities derived: {}", groupAuthorities.size());
			return groupAuthorities;
		}

		public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
			return Mono.just(jwt).map(this::doConversion);
		}
	}

}
