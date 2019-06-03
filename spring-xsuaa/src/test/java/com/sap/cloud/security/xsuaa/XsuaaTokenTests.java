package com.sap.cloud.security.xsuaa;

import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.jwt.Jwt;

public class XsuaaTokenTests {

    Jwt mockJwt;
    XsuaaToken token;
    
    @Before 
    public void setup() {
        Map<String, Object> headers = new HashMap<String, Object>();
        Map<String, Object> claims = new HashMap<String, Object>();
        
        headers.put("kid", "0");
        
        claims.put("scope", Arrays.asList("read", "write"));
        
        mockJwt = buildMockJwt(headers, claims);
        token = new XsuaaToken(mockJwt);
    }
    
    private Jwt buildMockJwt(Map<String, Object> jwtHeaders, Map<String, Object> jwtClaims) {
        return new Jwt("mockJwtValue", Instant.now(), Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
    }
    
    @Test
    public final void test_constructor() {
        new XsuaaToken(mockJwt);
    }

    @Test
    public final void testGetSubaccountId() {
        token.getSubaccountId();
    }

    @Test
    public final void testGetSubdomain() {
        token.getSubdomain();
    }

    @Test
    public final void testGetClientId() {
        token.getClientId();
    }

    @Test
    public final void testGetGrantType() {
        token.getGrantType();
    }

    @Test
    public final void testGetUserLoginName() {
        token.getUserLoginName();
    }

    @Test
    public final void testGetOrigin() {
        token.getOrigin();
    }

    @Test
    public final void testGetUniqueUserName() {
        token.getUniqueUserName();
    }

    @Test
    public final void testGetGivenName() {
        token.getGivenName();
    }

    @Test
    public final void testGetFamilyName() {
        token.getFamilyName();
    }

    @Test
    public final void testGetEmail() {
        token.getEmail();
    }

    @Test
    public final void testGetXSUserAttribute() {
        token.getXSUserAttribute("attrib");
    }

    @Test
    public final void testGetAdditionalAuthAttribute() {
        token.getAdditionalAuthAttribute("additionalAttrib");
    }

    @Test
    public final void testGetCloneServiceInstanceId() {
        token.getCloneServiceInstanceId();
    }

    @Test
    public final void testToString() {
        token.toString();
    }
}
