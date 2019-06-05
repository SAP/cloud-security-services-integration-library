package com.sap.cloud.security.xsuaa;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

public class XsuaaAudienceValidatorTests {

    private static final List<String> AUDIENCES = Arrays.asList("audience1", "audience2", "audience3", "", ".nullPrefixed", "aud.suffix");
    private static final List<String> SCOPES = Arrays.asList("read", "write", "", ".nullPrefixScope", "audience1.read");
    private static final String CLIENT_ID = "YOUR-CLIENT-ID";
    
    Jwt mockJwt;
    Map<String, Object> headers;
    Map<String, Object> claims;
    
    @Before
    public void setUp() throws Exception {
        headers = new HashMap<>();
        claims = new HashMap<>();
        
        headers.put("kid", "0");
        claims.put(XsuaaTokenClaims.CLAIM_CLIENT_ID, CLIENT_ID);
        claims.put(JwtClaimNames.AUD, AUDIENCES);
        claims.put(XsuaaTokenClaims.CLAIM_SCOPE, SCOPES);
        
        mockJwt = buildMockJwt(headers, claims);
    }

    @Test
    public final void test_constructor() throws IOException {
        ClassPathResource testResource = new ClassPathResource("vcap-services.json");
        File vcapServicesFile = testResource.getFile();
        
        DefaultXsuaaServiceBindings bindings = new DefaultXsuaaServiceBindings(vcapServicesFile);
        new XsuaaAudienceValidator(bindings);
    }
    
    @Test
    public final void test_constructor_throwsIf_bindingsAreNull() throws IOException {
        assertThatThrownBy(() -> {
            new XsuaaAudienceValidator(null);
        }).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Xsuaa service bindings must not be null");
    }

    @Test
    public final void test_validate() throws IOException {
        ClassPathResource testResource = new ClassPathResource("vcap-services.json");
        File vcapServicesFile = testResource.getFile();
        
        DefaultXsuaaServiceBindings bindings = new DefaultXsuaaServiceBindings(vcapServicesFile);
        XsuaaAudienceValidator validator = new XsuaaAudienceValidator(bindings);
        OAuth2TokenValidatorResult validationResult = validator.validate(mockJwt);
        assertFalse("Validation failed, but should not have.", validationResult.hasErrors());
        
        
        claims.remove(XsuaaTokenClaims.CLAIM_CLIENT_ID);
        mockJwt = buildMockJwt(headers, claims);
        validationResult = validator.validate(mockJwt);
        assertTrue("Validation should have failed, but has not.", validationResult.hasErrors());
        assertEquals(1, validationResult.getErrors().size());
        assertTrue(validationResult.getErrors().iterator().next().getDescription().contains("Jwt does not contain 'cid'"));
        
        claims.put(XsuaaTokenClaims.CLAIM_CLIENT_ID, "nonMatchingClientId");
        claims.put(JwtClaimNames.AUD, AUDIENCES);
        mockJwt = buildMockJwt(headers, claims);
        validationResult = validator.validate(mockJwt);
        assertTrue("Validation should have failed, but has not.", validationResult.hasErrors());
        assertEquals(1, validationResult.getErrors().size());
        assertTrue(validationResult.getErrors().iterator().next().getDescription().contains("Jwt token audience matches none of the following application IDs"));
        
        List<String> audienceMatchingXsAppName = new ArrayList<String>(AUDIENCES); 
        audienceMatchingXsAppName.add("YOUR-XS-APP-NAME");
        claims.put(XsuaaTokenClaims.CLAIM_CLIENT_ID, "nonMatchingClientId");
        claims.put(JwtClaimNames.AUD, audienceMatchingXsAppName);
        mockJwt = buildMockJwt(headers, claims);
        validationResult = validator.validate(mockJwt);
        assertFalse("Validation should have succeeded, but has not.", validationResult.hasErrors());
    }
    
    

    @Test
    public final void test_getAllowedAudiences() throws IOException {
        ClassPathResource testResource = new ClassPathResource("vcap-services.json");
        File vcapServicesFile = testResource.getFile();
        
        DefaultXsuaaServiceBindings bindings = new DefaultXsuaaServiceBindings(vcapServicesFile);
        XsuaaAudienceValidator validator = new XsuaaAudienceValidator(bindings);
        List<String> audiences = validator.getAllowedAudiences(mockJwt);
        assertNotNull(audiences);
        assertEquals(AUDIENCES.size()-2, audiences.size()); // should have filtered out empty audience ("") and 
                                                            // the null-prefixed one (".nullPrefixed").
        
        claims.remove(JwtClaimNames.AUD);
        mockJwt = buildMockJwt(headers, claims);
        audiences = validator.getAllowedAudiences(mockJwt);
        assertNotNull(audiences);
        assertEquals(1, audiences.size());
        
        claims.put(JwtClaimNames.AUD, new ArrayList<String>());
        mockJwt = buildMockJwt(headers, claims);
        audiences = validator.getAllowedAudiences(mockJwt);
        assertNotNull(audiences);
        assertEquals(1, audiences.size());
    }

    @Test
    public final void test_getScopes() throws IOException {
        ClassPathResource testResource = new ClassPathResource("vcap-services.json");
        File vcapServicesFile = testResource.getFile();
        
        DefaultXsuaaServiceBindings bindings = new DefaultXsuaaServiceBindings(vcapServicesFile);
        XsuaaAudienceValidator validator = new XsuaaAudienceValidator(bindings);
        List<String> scopes = validator.getScopes(mockJwt);
        assertNotNull(scopes);
        assertEquals(SCOPES.size(), scopes.size());
 
        claims.remove(XsuaaTokenClaims.CLAIM_SCOPE);
        Jwt mockJwt = buildMockJwt(headers, claims);
        scopes = validator.getScopes(mockJwt);
        assertNotNull(scopes);
        assertTrue(scopes.isEmpty());
    }

    private Jwt buildMockJwt(Map<String, Object> jwtHeaders, Map<String, Object> jwtClaims) {
        return new Jwt("mockJwtValue", Instant.now(), Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
    }
}
