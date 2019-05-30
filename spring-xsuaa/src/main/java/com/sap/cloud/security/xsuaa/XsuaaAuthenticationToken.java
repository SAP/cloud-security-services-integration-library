package com.sap.cloud.security.xsuaa;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Internal class used to expose the {@link XsuaaToken}
 * implementation as the standard Principal for Spring
 * Security Jwt handling.
 * 
 * @see XsuaaTokenConverter
 * @see XsuaaToken
 */
class XsuaaAuthenticationToken extends JwtAuthenticationToken {
    
    private static final long serialVersionUID = 111123011147092162L;

    public XsuaaAuthenticationToken(Jwt jwt, Collection<? extends GrantedAuthority> authorities) {
        super(jwt, authorities);
    }

    @Override
    public Object getPrincipal() {
        // Here is where the actual magic happens. 
        // The Jwt is exchanged for another implementation.
        return new XsuaaToken(getToken());
    }
}
