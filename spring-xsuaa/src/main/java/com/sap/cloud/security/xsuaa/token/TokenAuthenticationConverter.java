package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class TokenAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private String appId;

    public TokenAuthenticationConverter(String appId) {
        this.appId = appId;
    }

    public TokenAuthenticationConverter(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
        this.appId = xsuaaServiceConfiguration.getAppId();
    }


    public final AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        return new AuthenticationToken(appId, jwt, authorities);
    }

    protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        Collection<String> scopes = this.getScopes(jwt);
        return scopes.stream().map(authority -> authority).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    private Collection<String> getScopes(Jwt jwt) {
        List<String> scopesList = jwt.getClaimAsStringList(Token.CLAIM_SCOPES);
        return scopesList != null ? scopesList : Collections.emptyList();
    }
}