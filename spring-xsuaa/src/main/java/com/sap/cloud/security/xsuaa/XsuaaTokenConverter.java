package com.sap.cloud.security.xsuaa;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Converter to transform a Jwt token into 
 * a Spring Security AbstractAuthenticationToken.
 * 
 * <p>
 * Spring Security uses this mechanism to make the 
 * authentication token independent of the security 
 * standard, in this case Jwt token.
 * </p>
 * <p>
 * This class is also responsible for exchanging the standard 
 * Spring Security Jwt implementation for an instance of
 * class {@link XsuaaToken}.
 * </p>
 */
public class XsuaaTokenConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    
    private AuthoritiesExtractor authoritiesExtractor;
    
    /**
     * Creates a new converter with a new {@link DefaultSpringSecurityAuthoritiesExtractor}
     * instance as default authorities extractor. 
     */
    public XsuaaTokenConverter() {
        authoritiesExtractor = new DefaultSpringSecurityAuthoritiesExtractor();
    }
    
    /**
     * Creates a new converter with the given {@link AuthoritiesExtractor}.
     * @param authoritiesExtractor - the extractor used to turn Jwt scopes into Spring Security authorities.
     */
    public XsuaaTokenConverter(AuthoritiesExtractor authoritiesExtractor) {
        this.authoritiesExtractor = authoritiesExtractor;
    }

    /* (non-Javadoc)
     * @see org.springframework.core.convert.converter.Converter#convert(java.lang.Object)
     */
    @Override
    public AbstractAuthenticationToken convert(Jwt source) {
        Collection<GrantedAuthority> grantedAuthorities = authoritiesExtractor.getAuthorities(source);
        return new XsuaaAuthenticationToken(source, grantedAuthorities);
    }
}