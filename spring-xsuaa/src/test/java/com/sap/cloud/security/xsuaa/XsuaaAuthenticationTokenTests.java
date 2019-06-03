package com.sap.cloud.security.xsuaa;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class XsuaaAuthenticationTokenTests {

    Jwt mockJwt = buildMockJwt(Arrays.asList("read", "write"));
    Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
    
    @Test
    public void test_constructor() {
        new XsuaaAuthenticationToken(mockJwt, authorities); 
    }
    
    @Test
    public void test_getPrincipal() {
        XsuaaAuthenticationToken authToken = new XsuaaAuthenticationToken(mockJwt, authorities);
        Object principal = authToken.getPrincipal();
        assertNotNull("XsuaaAuthenticationToken getPrincipal() must not return null.", principal);
        assertTrue("XsuaaAuthenticationToken should return an XsuaaToken instance", principal instanceof XsuaaToken);
    }
    
    private Jwt buildMockJwt(List<String> scopes) {
        Map<String, Object> jwtHeaders = new HashMap<String, Object>();
        jwtHeaders.put("dummyHeader", "dummyHeaderValue");
        
        Map<String, Object> jwtClaims = new HashMap<String, Object>();
        jwtClaims.put("dummyClaim", "dummyClaimValue");
        jwtClaims.put("scope", scopes);
        
        return new Jwt("mockJwtValue", Instant.now(), Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
    }

}
