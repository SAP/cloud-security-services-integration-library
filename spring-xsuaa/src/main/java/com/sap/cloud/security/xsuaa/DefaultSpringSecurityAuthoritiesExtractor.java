package com.sap.cloud.security.xsuaa;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

/**
 * An implementation that exposes the default Spring Security behaviour of extracting authorities from a JWT.
 * Basically this class provides easy access to the otherwise protected {@link JwtAuthenticationConverter#extractAuthorities(Jwt)}
 * method. 
 * 
 * At the time of writing this, there is no better way to do this, since {@link JwtAuthenticationConverter#convert(Jwt)}
 * is declared final and hence directly deriving XSUAATokenConverter from it would return the wrong AuthenticationToken type.
 * Therefore, this class was created and is used as a possible input to XSUAATokenConverter.
 */
public class DefaultSpringSecurityAuthoritiesExtractor extends JwtAuthenticationConverter implements AuthoritiesExtractor {
    public Collection<GrantedAuthority> getAuthorities(Jwt jwt) {
        return extractAuthorities(jwt);
    }
}
