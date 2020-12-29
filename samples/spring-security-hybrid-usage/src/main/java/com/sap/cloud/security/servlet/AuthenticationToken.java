package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.Token;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Objects;

/**
 * Internal class used to expose the {@link Token} implementation as the
 * standard Principal for Spring Security Jwt handling.
 *
 */
// TODO move to the right package, when Token.create() was implemented
public class AuthenticationToken extends JwtAuthenticationToken {
    private static final long serialVersionUID = -3779129534612771294L;
    private final Token token;

    public AuthenticationToken(Jwt jwt, Collection<GrantedAuthority> grantedAuthorities) {
        super(jwt, grantedAuthorities);
        Assert.notNull(getToken().getTokenValue(), "Jwt needs to provide a token value.");
        this.token = TokenFactory.create(getToken().getTokenValue()); // TODO replace with Token.create()
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public String getName() {
       return token.getPrincipal().getName(); // TODO is that correct?
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && this.getClass() != obj.getClass()) {
            return false;
        }
        if (obj == null) {
            return false;
        }
        AuthenticationToken that = (AuthenticationToken) obj;
        return this.token.equals(that.token) && this.getAuthorities().equals(that.getAuthorities());
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), getToken());
    }


}
