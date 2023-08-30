/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.security;

import com.sap.cloud.security.spring.config.IdentityServicesPropertySourceFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity(debug = true) // TODO "debug" may include sensitive information. Do not use in a production system!
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, ignoreResourceNotFound = true, value = { "" })
public class SecurityConfiguration {

    @Autowired
    Converter<Jwt, AbstractAuthenticationToken> authConverter; // Required only when Xsuaa is used

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/sayHello").hasAuthority("Read")
                .antMatchers("/comp/sayHello").hasAuthority("Read")
                .antMatchers("/*").authenticated()
                .anyRequest().denyAll()
                .and()
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(new HybridConverter(authConverter)); // Adjust the converter to represent your use case
        // @formatter:on
        return http.build();
    }
}
