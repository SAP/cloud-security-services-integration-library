package com.sap.cloud.security.token.xsuaa;

import com.sap.cloud.security.servlet.HybridJwtDecoder;
import com.sap.cloud.security.test.JwtGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.junit.jupiter.api.Assertions.*;

class XsuaaTokenAuthenticationConverterTest {
    String xsAppName = "my-app-name!400";
    JwtGenerator jwtGenerator = JwtGenerator.getInstance(XSUAA, "theClientId").withAppId(xsAppName);
    XsuaaTokenAuthenticationConverter cut = new XsuaaTokenAuthenticationConverter(xsAppName);
    String scopeAdmin = xsAppName + "." + "Admin";
    String scopeRead = xsAppName + "." + "Read";
    String scopeOther = "other-app!234" + "." + "Other";

    @Test
    void convert() {
        jwtGenerator.withScopes(scopeAdmin, scopeOther, scopeRead);
        Jwt jwt = HybridJwtDecoder.parseJwt(jwtGenerator.createToken());

        AbstractAuthenticationToken token = cut.convert(jwt);

        assertEquals(2, token.getAuthorities().size());
        assertTrue(token.getAuthorities().contains(new SimpleGrantedAuthority("Admin")));
        assertTrue(token.getAuthorities().contains(new SimpleGrantedAuthority("Read")));
    }

    @Test
    void localScopeAuthorities() {
        jwtGenerator.withScopes(scopeAdmin, scopeOther, scopeRead);
        Jwt jwt = HybridJwtDecoder.parseJwt(jwtGenerator.createToken());

        Collection<GrantedAuthority> grantedAuthorities = cut.localScopeAuthorities(jwt);

        assertEquals(2, grantedAuthorities.size());
        assertTrue(grantedAuthorities.contains(new SimpleGrantedAuthority("Admin")));
        assertTrue(grantedAuthorities.contains(new SimpleGrantedAuthority("Read")));
    }
}