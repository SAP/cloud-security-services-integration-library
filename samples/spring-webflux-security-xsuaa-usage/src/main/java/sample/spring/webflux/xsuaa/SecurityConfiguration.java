package sample.spring.webflux.xsuaa;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import com.sap.cloud.security.xsuaa.token.ReactiveTokenAuthenticationConverter;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfiguration {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
		http.authorizeExchange().anyExchange().authenticated()
				.and().oauth2ResourceServer().jwt()
				.jwtAuthenticationConverter(new ReactiveTokenAuthenticationConverter(xsuaaServiceConfiguration))
				.jwtDecoder(new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration)
						.withPostValidationActions(token -> logger.info("post validation action performed"))
						.buildAsReactive());
		return http.build();
	}

}
