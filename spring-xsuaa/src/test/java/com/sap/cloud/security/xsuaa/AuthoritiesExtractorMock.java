package com.sap.cloud.security.xsuaa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class AuthoritiesExtractorMock implements AuthoritiesExtractor {

    Jwt expectedJwt; 
    boolean getAuthoritiesCalled;
    
    public AuthoritiesExtractorMock(Jwt expectedJwt) {
        this.expectedJwt = expectedJwt;
    }
    
    @Override
    public Collection<GrantedAuthority> getAuthorities(Jwt jwt) {
        assertEquals("Jwt does not match expected Jwt", jwt, expectedJwt);
        getAuthoritiesCalled = true;
        return new ArrayList<GrantedAuthority>();
    }

    public void validateCallStack() {
        assertTrue("GetAuthorities() was not called.", getAuthoritiesCalled);
    }
}
