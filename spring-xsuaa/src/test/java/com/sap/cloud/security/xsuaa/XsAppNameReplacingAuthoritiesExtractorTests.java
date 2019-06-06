package com.sap.cloud.security.xsuaa;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
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
    public final void test_extractAuthorities_withDefaultPrefixReplacement() {
        XsAppNameReplacingAuthoritiesExtractor extractor = new XsAppNameReplacingAuthoritiesExtractor();
        
        List<String> scopes = Arrays.asList("sb-12345!b1245|xsAppName!b1245.read_broker", "sb-12345!b1245|xsAppName!b1245.write_broker", "xsAppName!b1245.read_foreign", "xsAppName!b1245.write_foreign");
        Jwt mockJwt = buildMockJwt(scopes);
        
        Collection<GrantedAuthority> authorities = extractor.extractAuthorities(mockJwt);
        assertNotNull("Authorities must not be null", authorities);
        assertEquals("Authorities size does not match number of scopes.", scopes.size(), authorities.size());
       
        List<String> authorityStrings = new ArrayList<String>(authorities.size());
        for(GrantedAuthority authority : authorities) {
            authorityStrings.add(authority.getAuthority());
        }
        
        assertTrue(authorityStrings.contains("SCOPE_read_broker"));
        assertTrue(authorityStrings.contains("SCOPE_write_broker"));
        assertTrue(authorityStrings.contains("SCOPE_read_foreign"));
        assertTrue(authorityStrings.contains("SCOPE_write_foreign"));
    }

    @Test
    public final void test_extractAuthorities() {
        List<String> scopes = Arrays.asList("read", "write");
        Jwt mockJwt = buildMockJwt(scopes);
        
        XsAppNameReplacingAuthoritiesExtractor extractor = new XsAppNameReplacingAuthoritiesExtractor();
        Collection<GrantedAuthority> grantedAuthorities = extractor.extractAuthorities(mockJwt);
        
        assertNotNull("Authorities must not be null.", grantedAuthorities);
        assertEquals("Number of granted authorities should equal number of scopes.", grantedAuthorities.size(), scopes.size());
        for(GrantedAuthority authority : grantedAuthorities) {
            assertTrue("Authorities should contain SCOPE_ prefix.", authority.getAuthority().startsWith("SCOPE_"));
            assertTrue("Authority not contained in scopes", scopes.contains(authority.getAuthority().replaceFirst("SCOPE_", "")));
        }
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
