package com.sap.cloud.security.samples;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity//(debug = true)
//@EnableOAuth2Sso
// https://spring.io/guides/tutorials/spring-boot-oauth2/
// https://www.baeldung.com/spring-security-openid-connect
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // keep / open, everything else only with authentication
        http.antMatcher("/**").authorizeRequests()
                .antMatchers("/health").permitAll()
                //.antMatchers(GET, "/").hasAuthority("read")
                //.antMatchers(POST, "/").hasAuthority('write')
                //.antMatchers("/salesOrders").hasAuthority('read:SalesOrders')
                .anyRequest().authenticated()
                .and().oauth2Login(); // TODO use @EnableOAuth2Sso
    }
}
