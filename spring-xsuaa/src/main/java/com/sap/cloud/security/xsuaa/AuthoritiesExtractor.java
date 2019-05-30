package com.sap.cloud.security.xsuaa;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public interface AuthoritiesExtractor {
    /**
     * Returns the granted authorities based on the 
     * information in the Jwt. A standard implementation
     * will base the granted authorities on the scopes.
     * 
     * Implementations can use this method to map / manipulate
     * scopes, e.g. by changing their prefix, etc.
     * 
     * @param jwt the Jwt to extract the authorities from.
     * @return the collection of granted authorities.
     */
    Collection<GrantedAuthority> getAuthorities(Jwt jwt);
}
