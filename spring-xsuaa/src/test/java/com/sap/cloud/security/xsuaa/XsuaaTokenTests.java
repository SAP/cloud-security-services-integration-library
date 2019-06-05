package com.sap.cloud.security.xsuaa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.jwt.Jwt;

public class XsuaaTokenTests {

    private static final String[] EXTERNAL_CONTEXT_ATTRIB_VALUE = new String[]{ "1", "2", "3"};
    private static final String EXTERNAL_CONTEXT_ATTRIB = "ExternalContextAttrib";
    Jwt mockJwt;
    XsuaaToken token;
    Map<String, Object> headers; 
    Map<String, Object> claims;
    
    private static final String ZONE_ID = "zoneId";
    private static final List<String> SCOPES = Arrays.asList("read", "write");
    private static final String SUBDOMAIN = "subdomain";
    private static final String CLIENT_ID = "clientID";
    private static final String GRANT_TYPE = "grantType";
    private static final String USER_NAME = "userName";
    private static final String ORIGIN = "origin";
    private static final String GIVEN_NAME = "givenName";
    private static final String FAMILY_NAME = "familyName";
    private static final String EMAIL = "some@one.com";
    private static final String ADDITIONAL_AZ_ATTRIB = "AdditionalAuthZAttributes";
    private static final String ADDITIONAL_AZ_ATTRIBUTE_VALUE = "AdditionalAuthzAttrribute";
    private static final String CLONE_SERVICE_INSTANCE_ID = "CloneServiceInstanceId";
    
    private static Map<String, Object> externalAttributes = new HashMap<String, Object>();
    
    @Before 
    public void setup() {
        headers = new HashMap<String, Object>();
        claims = new HashMap<String, Object>();
        
        headers.put("kid", "0");
        
        externalAttributes.put(XsuaaTokenClaims.CLAIM_ZDN, SUBDOMAIN);
        externalAttributes.put(XsuaaTokenClaims.CLAIM_GIVEN_NAME, GIVEN_NAME);
        externalAttributes.put(XsuaaTokenClaims.CLAIM_FAMILY_NAME, FAMILY_NAME);
        externalAttributes.put(XsuaaTokenClaims.CLAIM_SERVICEINSTANCEID, CLONE_SERVICE_INSTANCE_ID);
        externalAttributes.put(EXTERNAL_CONTEXT_ATTRIB, EXTERNAL_CONTEXT_ATTRIB_VALUE);
        externalAttributes.put(ADDITIONAL_AZ_ATTRIB, ADDITIONAL_AZ_ATTRIBUTE_VALUE);
        
        claims.put(XsuaaTokenClaims.CLAIM_SCOPE, SCOPES);
        claims.put(XsuaaTokenClaims.CLAIM_ZONE_ID, ZONE_ID);
        claims.put(XsuaaTokenClaims.CLAIM_EXTERNAL_ATTR, externalAttributes);
        claims.put(XsuaaTokenClaims.CLAIM_CLIENT_ID, CLIENT_ID);
        claims.put(XsuaaTokenClaims.CLAIM_GRANT_TYPE, GRANT_TYPE);
        claims.put(XsuaaTokenClaims.CLAIM_USER_NAME, USER_NAME);
        
        claims.put(XsuaaTokenClaims.CLAIM_ORIGIN, ORIGIN);
        claims.put(XsuaaTokenClaims.CLAIM_USER_NAME, USER_NAME);
        claims.put(XsuaaTokenClaims.CLAIM_USER_NAME, USER_NAME);
        claims.put(XsuaaTokenClaims.CLAIM_USER_NAME, USER_NAME);
        claims.put(XsuaaTokenClaims.CLAIM_EMAIL, EMAIL);
        claims.put(XsuaaTokenClaims.CLAIM_EXTERNAL_CONTEXT, externalAttributes);
        claims.put(XsuaaTokenClaims.CLAIM_ADDITIONAL_AZ_ATTR, externalAttributes);
        
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
        String zoneId = token.getSubaccountId();
        assertNotNull("ZoneId must not be null.", zoneId);
        assertEquals("ZoneId not as expected.", ZONE_ID, zoneId);
    }

    @Test
    public final void testGetSubdomain() {
        String subdomain = token.getSubdomain();
        assertNotNull("Subdomain must not be null.", subdomain);
        assertEquals("Subdomain not as expected.", SUBDOMAIN, subdomain);
    }

    @Test
    public final void testGetClientId() {
        String clientId = token.getClientId();
        assertNotNull("ClientID must not be null.", clientId);
        assertEquals("Client ID not as expected.", CLIENT_ID, clientId);
    }

    @Test
    public final void testGetGrantType() {
        String grantType = token.getGrantType();
        assertNotNull("Grant type must not be null.", grantType);
        assertEquals("Grant type not as expected.", GRANT_TYPE, grantType);
    }

    @Test
    public final void testGetUserLoginName() {
        String userName = token.getUserLoginName();
        assertNotNull("User name must not be null.", userName); 
        assertEquals("User name not as expected.", USER_NAME, userName);
    }

    @Test
    public final void testGetOrigin() {
        String origin = token.getOrigin();
        assertNotNull("Origin name must not be null.", origin); 
        assertEquals("Origin name not as expected.", ORIGIN, origin);
    }

    @Test
    public final void testGetUniqueUserName() {
        String uniqueUserName = token.getUniqueUserName();
        assertNotNull("Unique user name should not be null.", uniqueUserName);
        assertTrue("Unique user name should start with 'user' for grant flows other than client-credentials-flow.", uniqueUserName.startsWith("user"));
        assertTrue("Unique user name should include origin for grant flows other than client-credentials-flow.", uniqueUserName.contains(token.getOrigin()));
        assertTrue("Unique user name should include user login name for grant flows other than client-credentials-flow.", uniqueUserName.contains(token.getUserLoginName()));
        
        claims.put(XsuaaTokenClaims.CLAIM_GRANT_TYPE, "client_credentials");
        mockJwt = buildMockJwt(headers, claims);
        token = new XsuaaToken(mockJwt);
        uniqueUserName = token.getUniqueUserName();
        assertNotNull("Unique user name should not be null.", uniqueUserName);
        assertTrue("Unique user name should start with 'client' for grant flow client-credentials-flow.", uniqueUserName.startsWith("client"));
        assertFalse("Unique user name should NOT include origin for grant flow client-credentials-flow.", uniqueUserName.contains(token.getOrigin()));
        assertTrue("Unique user name should include client ID for grant flow client-credentials-flow.", uniqueUserName.contains(token.getClientId()));
        
        claims.put(XsuaaTokenClaims.CLAIM_GRANT_TYPE, "client_credentials");
        claims.remove(XsuaaTokenClaims.CLAIM_ORIGIN);
        mockJwt = buildMockJwt(headers, claims);
        token = new XsuaaToken(mockJwt);
        uniqueUserName = token.getUniqueUserName();
        assertNotNull("If origin is null, and grant is client_credentials grant, unique user name should not be null, even if origin is.", uniqueUserName);
        
        claims.put(XsuaaTokenClaims.CLAIM_GRANT_TYPE, "any grant");
        claims.remove(XsuaaTokenClaims.CLAIM_ORIGIN);
        mockJwt = buildMockJwt(headers, claims);
        token = new XsuaaToken(mockJwt);
        uniqueUserName = token.getUniqueUserName();
        assertNull("If origin is null, unique user name should be null too, except for client_credentials grant.", uniqueUserName);
        
        claims.put(XsuaaTokenClaims.CLAIM_GRANT_TYPE, "any grant");
        claims.put(XsuaaTokenClaims.CLAIM_ORIGIN, "notNullOrigin");
        claims.remove(XsuaaTokenClaims.CLAIM_USER_NAME);
        mockJwt = buildMockJwt(headers, claims);
        token = new XsuaaToken(mockJwt);
        uniqueUserName = token.getUniqueUserName();
        assertNull("If user name is null, unique user name should be null too, except for client_credentials grant.", uniqueUserName);
        
        claims.put(XsuaaTokenClaims.CLAIM_GRANT_TYPE, "any grant");
        claims.put(XsuaaTokenClaims.CLAIM_ORIGIN, "illegal/origin");
        claims.put(XsuaaTokenClaims.CLAIM_USER_NAME, "notNullUser");
        mockJwt = buildMockJwt(headers, claims);
        token = new XsuaaToken(mockJwt);
        uniqueUserName = token.getUniqueUserName();
        assertNull("If origin is illegally containing slashes, unique user name should be null, except for client_credentials grant.", uniqueUserName);
    }

    @Test
    public final void testGetGivenName() {
        String givenName = token.getGivenName();
        assertNotNull("Given name must not be null.", givenName);
        assertEquals("Given name not as expected.", GIVEN_NAME, givenName);
    }

    @Test
    public final void testGetFamilyName() {
        String familyName = token.getFamilyName();
        assertNotNull("Family name must not be null.", familyName);
        assertEquals("Family name not as expected.", FAMILY_NAME, familyName);
    }

    @Test
    public final void testGetEmail() {
        String email = token.getEmail();
        assertNotNull("Email must not be null.", email);
        assertEquals("Email not as expected.", EMAIL, email);
    }

    @Test
    public final void testGetXSUserAttribute() {
        String[] xsUserAttribute = token.getXSUserAttribute(EXTERNAL_CONTEXT_ATTRIB);
        assertNotNull("XS User Attributes must not be null.", xsUserAttribute);
        assertEquals("XS User Attributes size incorrect.", EXTERNAL_CONTEXT_ATTRIB_VALUE.length, xsUserAttribute.length);
        List<String> xsUserAttributes = Arrays.asList(xsUserAttribute);
        for(String attrib : EXTERNAL_CONTEXT_ATTRIB_VALUE) {
            assertTrue("Could not find all expected xs user attributes.", xsUserAttributes.contains(attrib));
        }
    }

    @Test
    public final void testGetAdditionalAuthAttribute() {
        String additionalAuthzAttrib = token.getAdditionalAuthAttribute(ADDITIONAL_AZ_ATTRIB);
        assertNotNull("Additional Authz Attributes must not be null.", additionalAuthzAttrib);
        assertEquals("Addition Authz Attribute not as expected.", ADDITIONAL_AZ_ATTRIBUTE_VALUE, additionalAuthzAttrib);
    }

    @Test
    public final void testGetCloneServiceInstanceId() {
        String cloneServiceInstanceId = token.getCloneServiceInstanceId();
        assertNotNull("Clone service instance ID must not be null.", cloneServiceInstanceId);
        assertEquals("Clone service instance ID not as expected.", CLONE_SERVICE_INSTANCE_ID, cloneServiceInstanceId);
    }

    @Test
    public final void testToString() {
        String toString = token.toString();
        assertNotNull("toString() method must not return null.", toString);
        assertTrue("toString() must contain headers information.", toString.contains("Headers"));
        assertTrue("toString() must contain claims information.", toString.contains("Claims"));
        assertTrue("toString() must contain encoded JWT value information.", toString.contains("Encoded Value"));
    }
}
