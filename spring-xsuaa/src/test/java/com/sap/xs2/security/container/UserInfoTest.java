package com.sap.xs2.security.container;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

public class UserInfoTest {

    private UserInfo userInfo = null;
    private JWTClaimsSet.Builder claimsSetBuilder = null;
    private String xsAppName = "my-app-name!400";
    private String scopeRead = xsAppName + "." + "Display";
    private String scopeWrite = xsAppName + "." + "Edit";
    private String userName = "testUser";

    @Before
    public void setup() {
        claimsSetBuilder = new JWTClaimsSet.Builder()
                .issueTime(new Date())
                .expirationTime(UserInfoTestUtil.NO_EXPIRE)
                .claim("user_name", userName)
                .claim("user_id", "D012345")
                .claim("email", userName + "@test.org")
                .claim("zid", "myIdentityZone")
                .claim("origin", "userIdp")
                .claim("grant_type", UserInfo.GRANTTYPE_SAML2BEARER);
    }

    @Test
    public void checkBasicJwtWithoutScopes() throws Exception {
        userInfo = UserInfoTestUtil.createFromClaims(claimsSetBuilder.build(), xsAppName);

        assertThat(userInfo.getLogonName(), is(userName));
        assertThat(userInfo.getPassword(), nullValue());
        assertThat(userInfo.getOrigin(), is("userIdp"));
        assertThat(userInfo.isAccountNonLocked(), is(true));
        assertThat(userInfo.isAccountNonExpired(), is(true));
        assertThat(userInfo.getAuthorities().size(), is(0));
        assertThat(userInfo.isEnabled(), is(false));
    }

    @Test
    public void getAuthoritiesReturnsManyScopes() throws Exception {
        List<String> scopesList = new ArrayList<>();
        scopesList.add(scopeWrite);
        scopesList.add(scopeRead);
        claimsSetBuilder.claim("scope", scopesList);

        userInfo = UserInfoTestUtil.createFromClaims(claimsSetBuilder.build(), xsAppName);

        Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) userInfo.getAuthorities();
        assertThat(authorities.size(), is(2));
        assertThat(authorities, hasItem(new SimpleGrantedAuthority(scopeRead)));
        assertThat(authorities, hasItem(new SimpleGrantedAuthority(scopeWrite)));
    }

    @Test
    public void getAuthoritiesNoScopeClaimReturnsEmptyList() throws Exception {
        claimsSetBuilder.claim("scope",  new ArrayList<>());

        userInfo = UserInfoTestUtil.createFromClaims(claimsSetBuilder.build(), xsAppName);

        Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) userInfo.getAuthorities();
        assertThat(authorities.size(), is(0));
    }

    @Test
    public void isCredentialsExpiredWhenExpiryDateExceeded() throws Exception {
        claimsSetBuilder.issueTime(new Date(System.currentTimeMillis() - 300000));
        claimsSetBuilder.expirationTime(new Date(System.currentTimeMillis() - 20000));
        userInfo = UserInfoTestUtil.createFromClaims(claimsSetBuilder.build(), xsAppName);
        assertThat(userInfo.isCredentialsNonExpired(), is(false));
    }

    @Test
    public void getUserNameIsUniqueWithOrigin() throws Exception {
        userInfo = UserInfoTestUtil.createFromClaims(claimsSetBuilder.build(), xsAppName);
        assertThat(userInfo.getUsername(), is("userIdp/testUser"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void getUserNameReturnsErrorWhenOriginContainsDelimeterChar() throws Exception {
        claimsSetBuilder.claim("origin", "user/Idp");
        userInfo = UserInfoTestUtil.createFromClaims(claimsSetBuilder.build(), xsAppName);
        userInfo.getUsername();
    }
}
