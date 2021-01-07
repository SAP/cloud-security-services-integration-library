package com.sap.cloud.security.token.xsuaa;

import com.sap.cloud.security.servlet.AuthenticationToken;
import com.sap.cloud.security.token.TokenClaims;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;

/**
 * An authentication converter that extracts authorization related information
 * from the Jwt token. For example it removes the ugly application id
 * prefix (e.g.my-application-demo!t1229) from the scopes in the JWT.
 */
public class XsuaaTokenAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private String appId;

    /**
     * @param appId the xsuaa application identifier
     *            e.g. myXsAppname!t123
     */
    public XsuaaTokenAuthenticationConverter(String appId) {
        this.appId = appId;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        return new AuthenticationToken(jwt, localScopeAuthorities(jwt));
    }

    protected Collection<GrantedAuthority> localScopeAuthorities(Jwt jwt) {
        Collection<GrantedAuthority> localScopeAuthorities = new ArrayList<>();
        Collection<String> scopes = jwt.getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
        if (scopes == null) {
            return Collections.emptySet();
        }
        for (String scope: scopes) {
            if(scope.startsWith(appId + ".")) {
                localScopeAuthorities.add(new SimpleGrantedAuthority(scope.replaceFirst(appId + ".", "")));
            }
        }
        return localScopeAuthorities;
    }

}
