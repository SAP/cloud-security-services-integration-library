package com.webflux.xsuaa;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory;
import com.sap.cloud.security.xsuaa.token.ReactiveTokenAuthenticationConverter;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "classpath:" })
public class WebSecurityConfiguration {

	@Autowired
	XsuaaServiceConfigurationDefault xsuaaServiceConfiguration;

	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

		http.authorizeExchange().anyExchange().authenticated().and().oauth2ResourceServer().jwt()
				.jwtAuthenticationConverter(new ReactiveTokenAuthenticationConverter(xsuaaServiceConfiguration))
				.jwtDecoder(new XsuaaJwtDecoderBuilder(xsuaaServiceConfiguration).buildAsReactive());

		return http.build();
	}

	@Bean
	XsuaaServiceConfigurationDefault xsuaaConfig() {
		return new XsuaaServiceConfigurationDefault();
	}

}
