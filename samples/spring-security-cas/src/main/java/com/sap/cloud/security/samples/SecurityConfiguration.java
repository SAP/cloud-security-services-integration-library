package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.AdcService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.util.HashSet;
import java.util.Set;

import static org.springframework.http.HttpMethod.GET;

@Configuration
@EnableWebSecurity(debug = true)
// https://spring.io/guides/tutorials/spring-boot-oauth2/
// https://www.baeldung.com/spring-security-openid-connect
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    AdcService adcService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // keep / open, everything else only with authentication
        http.antMatcher("/**").authorizeRequests()
                .antMatchers("/health").permitAll()
                .antMatchers(GET, "/salesOrders").hasAuthority("read:salesOrders")
                .anyRequest().authenticated()
                .and().oauth2Login();
    }

    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        //https://docs.spring.io/spring-security/site/docs/5.0.7.RELEASE/reference/html/oauth2login-advanced.html#oauth2login-advanced-map-authorities-grantedauthoritiesmapper
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (OidcUserAuthority.class.isInstance(authority)) {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority)authority;

                    String userId = oidcUserAuthority.getIdToken().getSubject();
                    // TODO String zoneId = oidcUserAuthority.getIdToken();
                    // TODO request adc service for all "action:resource"-authorities
                    mappedAuthorities.add(new SimpleGrantedAuthority("read:salesOrders"));
                } else if (GrantedAuthority.class.isInstance(authority)) {
                    mappedAuthorities.add(authority);
                }
            });
            return mappedAuthorities;
        };
    }
}
