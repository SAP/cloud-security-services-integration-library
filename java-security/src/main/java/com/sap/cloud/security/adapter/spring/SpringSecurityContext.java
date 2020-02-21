package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

import javax.annotation.Nullable;
import java.util.Objects;

/**
 * This is an alternative way of accessing jwt tokens of type {@link Token} or {@link AccessToken}
 * in context of an application using spring-security-oauth2.
 *
 * It uses the {@link SecurityContextHolder} to access Spring's {@link SecurityContext}
 *  and can therefore used also in context of asynchronous threads.
 */
public class SpringSecurityContext {
    private static final Logger LOGGER = LoggerFactory.getLogger(SpringSecurityContext.class);

    private SpringSecurityContext() {
    }

    /**
     * Returns the token using {@link SecurityContextHolder}.
     *
     *
     * @return the token or <code>null</code> if {@link SecurityContext} is empty
     * or does not contain a token of this type.
     */
    @Nullable
    public static Token getToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(Objects.nonNull(authentication) && authentication.isAuthenticated() &&
                authentication.getDetails() instanceof OAuth2AuthenticationDetails) {
            OAuth2AuthenticationDetails authDetails = (OAuth2AuthenticationDetails) authentication.getDetails();
            String tokenValue = authDetails.getTokenValue();
            // TODO IAS Support
            return new XsuaaToken(tokenValue);
        }
        return null;
    }

    /**
     * Returns the token using {@link SecurityContextHolder}.
     *
     *
     * @return the token or <code>null</code> if {@link SecurityContext} is empty
     * or does not contain a token of this type.
     */
    @Nullable
    public static AccessToken getAccessToken() {
        Token token = getToken();
        return token instanceof AccessToken ? (AccessToken) token : null;
    }

    /**
     * Clears the context value from the current thread.
     */
    public static void clear() {
        SecurityContextHolder.clearContext();
    }

}

