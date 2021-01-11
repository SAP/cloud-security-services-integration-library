package com.sap.cloud.security.servlet;

import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.Token;
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

    JwtGenerator jwtGenerator = JwtGenerator.getInstance(IAS, "theClientId");

    Collection<GrantedAuthority> singleAuthority = Collections.singletonList(new SimpleGrantedAuthority("read"));

    @Test
    void equals() {
        Jwt jwt1 = Mockito.mock(Jwt.class);
        when(jwt1.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

        Jwt jwt2 = Mockito.mock(Jwt.class);
        when(jwt2.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

        AuthenticationToken cut = new AuthenticationToken(jwt1, null);

        assertTrue(cut.equals(new AuthenticationToken(jwt1, null)));
        assertTrue(cut.equals(new AuthenticationToken(jwt2, null)));
        assertTrue(new AuthenticationToken(jwt1, singleAuthority).equals(new AuthenticationToken(jwt2, singleAuthority)));

        assertEquals(cut.hashCode(), cut.hashCode());
        assertEquals(cut, new AuthenticationToken(jwt1, null));
    }

    @Test
    void notEquals() {
        Jwt jwt1 = Mockito.mock(Jwt.class);
        when(jwt1.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

        Jwt jwt2 = Mockito.mock(Jwt.class);
        jwtGenerator.withClaimValue("ext", "value");
        when(jwt2.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());

        AuthenticationToken cut = new AuthenticationToken(jwt1, null);
        assertFalse(cut.equals(new AuthenticationToken(jwt2, null)));
        assertFalse(cut.equals(null));
        assertFalse(cut.equals(Mockito.mock(Jwt.class)));
        assertFalse(cut.equals(new AuthenticationToken(jwt1, singleAuthority)));

        assertNotEquals(cut, new AuthenticationToken(jwt2, null));
    }

    @Test
    void getPrincipal() {
        Jwt jwt = Mockito.mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());
        Object principal = new AuthenticationToken(jwt, null).getPrincipal();
        assertTrue(principal instanceof Token);
        assertEquals("theClientId", ((Token)principal).getClientId());
    }

    @Test
    void getName() {
        Jwt jwt = Mockito.mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn(jwtGenerator.createToken().getTokenValue());
        assertEquals("the-user-id", new AuthenticationToken(jwt, null).getName());
    }
}
