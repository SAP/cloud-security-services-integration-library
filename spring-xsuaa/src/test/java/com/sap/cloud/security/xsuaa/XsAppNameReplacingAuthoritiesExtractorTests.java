package com.sap.cloud.security.xsuaa;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class XsAppNameReplacingAuthoritiesExtractorTests {

    @Test
    public final void test_constructor() {
        new XsAppNameReplacingAuthoritiesExtractor();
    }

    @Test
    public final void test_constructor_withMapOfStringString() {
        new XsAppNameReplacingAuthoritiesExtractor(new HashMap<String, String>());
    }
    
    @Test
    public final void test_constructor_withMapOfStringString_throwsOnNullValues() {
        assertThatThrownBy(() -> {
            new XsAppNameReplacingAuthoritiesExtractor(null);
        }).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Replacement Strings map must not be null"); 
    }

    @Test
    public final void test_extractAuthorities() {
        List<String> scopes = Arrays.asList("read", "write");
        Jwt mockJwt = buildMockJwt(scopes);
        
        XsAppNameReplacingAuthoritiesExtractor extractor = new XsAppNameReplacingAuthoritiesExtractor();
        Collection<GrantedAuthority> grantedAuthorities = extractor.extractAuthorities(mockJwt);
        
        assertEquals("Number of granted authorities should equal number of scopes.", grantedAuthorities.size(), scopes.size());
    }
    
    @Test
    public final void test_extractAuthorities_replacesPrefixes() {
        List<String> scopes = Arrays.asList("uglyPrefix.read", "uglyPrefix.write", "noPrefixScope");
        Jwt mockJwt = buildMockJwt(scopes);
        Map<String, String> replacements = new HashMap<String, String>();
        replacements.put("uglyPrefix", "nicerPrefix");
        
        XsAppNameReplacingAuthoritiesExtractor extractor = new XsAppNameReplacingAuthoritiesExtractor(replacements);
        Collection<GrantedAuthority> grantedAuthorities = extractor.extractAuthorities(mockJwt);
        
        assertEquals("Number of granted authorities should equal number of scopes.", grantedAuthorities.size(), scopes.size());
        
        for(GrantedAuthority grantedAuthority : grantedAuthorities) {
            if (grantedAuthority.getAuthority().contains(".")) {
                assertTrue("Prefix should have been replaced with values from replacement map.", grantedAuthority.getAuthority().contains("nicerPrefix"));
            }
            else {
                assertTrue("NoPrefixScope should not have been altered.", grantedAuthority.getAuthority().equals("SCOPE_noPrefixScope"));
            }
        }
    }

    @Test
    public final void test_getAuthorities() {
        List<String> scopes = Arrays.asList("read", "write");
        Jwt mockJwt = buildMockJwt(scopes);
        
        XsAppNameReplacingAuthoritiesExtractor extractor = new XsAppNameReplacingAuthoritiesExtractor();
        Collection<GrantedAuthority> grantedAuthorities = extractor.getAuthorities(mockJwt);
        
        assertEquals("Number of granted authorities should equal number of scopes.", grantedAuthorities.size(), scopes.size());
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
