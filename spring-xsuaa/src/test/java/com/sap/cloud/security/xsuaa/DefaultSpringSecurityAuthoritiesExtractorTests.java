package com.sap.cloud.security.xsuaa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class DefaultSpringSecurityAuthoritiesExtractorTests {
    
    Jwt jwt;

    @Test
    public void test_getAuthorities() {
        List<String> scopes = Arrays.asList("read", "write", "doit"); 
        jwt = buildMockJwt(scopes);
        DefaultSpringSecurityAuthoritiesExtractor extractor = new DefaultSpringSecurityAuthoritiesExtractor();
        Collection<GrantedAuthority> grantedAuthorities = extractor.getAuthorities(jwt);
       
        assertNotNull("Granted authorities are null but should not be. ", grantedAuthorities);
        assertEquals("Number of authorities does not match number of scopes in JWT.", grantedAuthorities.size(), scopes.size());
       
        assertAuthoritiesMatchScopes(scopes, grantedAuthorities);
    }

    private void assertAuthoritiesMatchScopes(List<String> scopes, Collection<GrantedAuthority> grantedAuthorities) {
        int expectedNumberOfMatches = 0;
        for (GrantedAuthority grantedAuthority : grantedAuthorities) {
            String authority = grantedAuthority.getAuthority();
            for (String scope : scopes) {
                if (authority.equals("SCOPE_" + scope)) {
                    expectedNumberOfMatches++;
                }
            }
        }
        
        assertEquals("Could not find all scopes extracted as authorities.", expectedNumberOfMatches, scopes.size());
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
