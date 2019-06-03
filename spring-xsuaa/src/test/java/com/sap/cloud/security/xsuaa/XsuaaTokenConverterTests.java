package com.sap.cloud.security.xsuaa;

import static org.junit.Assert.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.oauth2.jwt.Jwt;

public class XsuaaTokenConverterTests {
    
    Jwt mockJwt = buildMockJwt(Arrays.asList("read", "write"));

    @Test
    public final void test_constructor() {
        new XsuaaTokenConverter();
    }

    @Test
    public final void test_constructor_withAuthoritiesExtractor() {
        AuthoritiesExtractorMock extractorMock = new AuthoritiesExtractorMock(mockJwt);
        new XsuaaTokenConverter(extractorMock);
    }

    @Test
    public final void test_convert() {
        AuthoritiesExtractorMock extractorMock = new AuthoritiesExtractorMock(mockJwt);
        XsuaaTokenConverter converter = new XsuaaTokenConverter(extractorMock);
        converter.convert(mockJwt);
        extractorMock.validateCallStack();
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
