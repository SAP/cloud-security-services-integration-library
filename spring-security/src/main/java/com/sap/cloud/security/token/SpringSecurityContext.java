package com.sap.cloud.security.token;

import com.sap.cloud.security.token.authentication.HybridJwtDecoder;
import com.sap.cloud.security.token.authentication.XsuaaTokenAuthorizationConverter;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.Assert;

import javax.annotation.Nullable;

/**
 * This is an alternative way of accessing jwt tokens of type {@link Token} or
 * {@link AccessToken} in context of an application using
 * spring-security-oauth2.
 *
 * It uses the {@link SecurityContextHolder} to access Spring's
 * {@link SecurityContext} and can therefore used also in context of
 * asynchronous threads.
 */
public class SpringSecurityContext {

    private SpringSecurityContext() {
    }

    /**
     * Obtain the Token object using {@link SecurityContextHolder}.
     *
     *
     * @return Token instance or <code>null</code> if {@link SecurityContext} is empty or
     *         does not contain a token of this type.
     * @throws AccessDeniedException
     *             in case there is no token, user is not authenticated
     *             <p>
     *             Note: This method is introduced with xsuaa spring client lib.
     */
    @Nullable
    public static Token getToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Access forbidden: not authenticated");
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof Token) {
            return (Token) principal;
        }
        throw new AccessDeniedException(
                "Access forbidden: SecurityContextHolder does not contain a principal of type 'Token' " + principal);
    }

    /**
     * Obtain the Access Token from xsuaa service using {@link SecurityContextHolder}.
     *
     *
     * @return AccessToken instance or <code>null</code> if {@link SecurityContext} is empty or
     *         does not contain a token of this type.
     * @throws AccessDeniedException
     *             in case there is no token, user is not authenticated
     *             <p>
     *             Note: This method is introduced with xsuaa spring client lib.
     */
    @Nullable
    public static AccessToken getAccessToken() {
        Token token = getToken();
        return token instanceof AccessToken ? (AccessToken) token : null;
    }

    /**
     * Cleans up the Spring Security Context {@link SecurityContextHolder} and
     * release thread locals for Garbage Collector to avoid memory leaks resources.
     */
    public static void clear() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Initializes the Spring Security Context {@link SecurityContextHolder} and
     * extracts the authorities.
     *
     * @param encodedToken
     *            the jwt token that is decoded with the given JwtDecoder
     * @param jwtDecoder
     *            the decoder of type {@link JwtDecoder}
     */
    public static void init(String encodedToken, JwtDecoder jwtDecoder, String xsuaaAppId) {
        Assert.isInstanceOf(HybridJwtDecoder.class, jwtDecoder,
                "Passed JwtDecoder instance must be of type 'HybridJwtDecoder'");
        Jwt jwtToken = jwtDecoder.decode(encodedToken);

        Converter<Jwt, AbstractAuthenticationToken> authenticationConverter = new XsuaaTokenAuthorizationConverter(xsuaaAppId);
        Authentication authentication = authenticationConverter.convert(jwtToken);

        SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

}
