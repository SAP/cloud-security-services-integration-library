package com.sap.cloud.security.xsuaa.extractor;


import com.sap.cloud.security.xsuaa.token.XsuaaToken;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;

public class LocalAuthoritiesExtractorTest {
    LocalAuthoritiesExtractor cut;
    XsuaaToken token;
    Collection<String> scopes = new HashSet<>();

    @Before
    public void setup() {
        cut = new LocalAuthoritiesExtractor("appId!1234");

        token = Mockito.mock(XsuaaToken.class);
        scopes.add("appId!1234.Scope1");
        scopes.add("appId!1234.Scope2");
        scopes.add("appId2!888.Scope1");
        scopes.add("appId2!777.Scope3");
        Mockito.when(token.getScopes()).thenReturn(scopes);
    }

    @Test
    public void extractLocalScopes() {
        assertThat(cut.getAuthorities(token)).hasSize(2);
        assertThat(cut.getAuthorities(token)).contains(new SimpleGrantedAuthority("Scope1"));
        assertThat(cut.getAuthorities(token)).contains(new SimpleGrantedAuthority("Scope2"));
    }

    @Test
    public void extractLocalScopesOfTwoApps() {
        cut = new LocalAuthoritiesExtractor("appId!1234", "appId2!777");
        assertThat(cut.getAuthorities(token)).hasSize(3);
        assertThat(cut.getAuthorities(token)).contains(new SimpleGrantedAuthority("Scope1"));
        assertThat(cut.getAuthorities(token)).contains(new SimpleGrantedAuthority("Scope1"));
        assertThat(cut.getAuthorities(token)).contains(new SimpleGrantedAuthority("Scope3"));
    }

    @Test
    public void extractLocalScopesOfTwoApps_SameScopeName() {
        cut = new LocalAuthoritiesExtractor("appId!1234", "appId2!888");
        assertThat(cut.getAuthorities(token)).hasSize(2);
        assertThat(cut.getAuthorities(token)).contains(new SimpleGrantedAuthority("Scope1"));
        assertThat(cut.getAuthorities(token)).contains(new SimpleGrantedAuthority("Scope2"));
    }
}