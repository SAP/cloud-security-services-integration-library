package sample.spring.webflux.xsuaa;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
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

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

		http.authorizeExchange().anyExchange().authenticated()
				.and().oauth2ResourceServer().jwt()
				.jwtAuthenticationConverter(new ReactiveTokenAuthenticationConverter(xsuaaServiceConfiguration))
				.jwtDecoder(new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration).buildAsReactive());
		return http.build();
	}

}
