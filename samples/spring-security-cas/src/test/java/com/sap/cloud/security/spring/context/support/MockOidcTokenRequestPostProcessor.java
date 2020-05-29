package com.sap.cloud.security.spring.context.support;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.HashSet;
import java.util.Set;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;

/*public class MockOidcTokenRequestPostProcessor {

    public static RequestPostProcessor userToken(final String userName) {
        return oidcLogin().idToken(token -> token.claim("sub", userName));
    }

    public static RequestPostProcessor userTokenWithAuthorities(final String userName, final String... authorities) {
        Set<GrantedAuthority> grantedAuthoritySet = new HashSet<>();
        //grantedAuthoritySet.add(new SimpleGrantedAuthority("SCOPE_openid"));
        for (String authority: authorities) {
            grantedAuthoritySet.add(new SimpleGrantedAuthority(authority));
        }
        return oidcLogin()
                .idToken(token -> token.claim("sub", userName))
                .authorities(grantedAuthoritySet);
    }
}*/
