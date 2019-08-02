package sample.spring.webflux.xsuaa;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory;
import com.sap.cloud.security.xsuaa.token.ReactiveTokenAuthenticationConverter;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "" })
public class SecurityConfiguration {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
		http.authorizeExchange()
				.pathMatchers("/v1/sayHello").hasAuthority("Read")
				.and().oauth2ResourceServer().jwt()
				.jwtAuthenticationConverter(getJwtAuthenticationConverter())
				.jwtDecoder(new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration)
						.withPostValidationActions(token -> logger.info("post validation action performed"))
						.buildAsReactive());
		return http.build();
	}

	@Bean
	public XsuaaServiceConfiguration xsuaaServiceConfiguration() {
		return new XsuaaServiceConfigurationDefault();
	}

	/**
	 * Customizes how GrantedAuthority are derived from a Jwt
	 */
	Converter<Jwt, Mono<AbstractAuthenticationToken>> getJwtAuthenticationConverter() {
		ReactiveTokenAuthenticationConverter converter = new ReactiveTokenAuthenticationConverter(xsuaaServiceConfiguration);
		converter.setLocalScopeAsAuthorities(true);
		return converter;
	}

}
