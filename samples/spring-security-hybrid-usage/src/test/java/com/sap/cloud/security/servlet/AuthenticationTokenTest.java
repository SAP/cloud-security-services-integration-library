package com.sap.cloud.security.servlet;

import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.test.RSAKeys;
import com.sap.cloud.security.servlet.AuthenticationToken;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;

import static com.sap.cloud.security.config.Service.IAS;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

public class AuthenticationTokenTest {

    JwtGenerator jwtGenerator = JwtGenerator.getInstance(IAS, "theClientId")
            .withPrivateKey(RSAKeys.generate().getPrivate());

    Collection<GrantedAuthority> singleAuthority = Collections.singletonList(new SimpleGrantedAuthority("read"));

    @Test
    void equals() {
        Jwt jwt1 = Mockito.mock(Jwt.class);
        when(jwt1.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

        Jwt jwt2 = Mockito.mock(Jwt.class);
        when(jwt2.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

        assertTrue(new AuthenticationToken(jwt1, null).equals(new AuthenticationToken(jwt1, null)));
        assertTrue(new AuthenticationToken(jwt1, null).equals(new AuthenticationToken(jwt2, null)));
        assertTrue(new AuthenticationToken(jwt1, singleAuthority).equals(new AuthenticationToken(jwt2, singleAuthority)));
    }

    @Test
    void notEquals() {
        Jwt jwt1 = Mockito.mock(Jwt.class);
        when(jwt1.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

        Jwt jwt2 = Mockito.mock(Jwt.class);
        jwtGenerator.withClaimValue("ext", "value");
        when(jwt2.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

        assertFalse(new AuthenticationToken(jwt1, null).equals(new AuthenticationToken(jwt2, null)));
        assertFalse(new AuthenticationToken(jwt1, null).equals(null));
        assertFalse(new AuthenticationToken(jwt1, null).equals(Mockito.mock(Jwt.class)));
        assertFalse(new AuthenticationToken(jwt1, null).equals(new AuthenticationToken(jwt1, singleAuthority)));
    }
}
