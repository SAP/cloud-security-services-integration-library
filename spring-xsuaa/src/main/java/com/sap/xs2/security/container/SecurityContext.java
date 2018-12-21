package com.sap.xs2.security.container;

import com.sap.cloud.security.xsuaa.token.Token;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

public class SecurityContext {
    /**
     * Obtain the UserInfo object from the Spring SecurityContext
     *
     * @return UserInfo object
     * @throws UserInfoException
     * @deprecated use {@link #getToken()} instead.
     */
    @Deprecated
    static public UserInfo getUserInfo() throws UserInfoException {
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            if (SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof UserInfo) {
                return (UserInfo) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            } else {
                throw new UserInfoException("Unexpected principal type");
            }
        } else {
            throw new UserInfoException("Not authenticated");
        }
    }

    /**
     * Obtain the Token object from the Spring SecurityContext
     *
     * @return Token object
     * @throws IllegalStateException
     */
    static public Token getToken() throws  IllegalStateException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Assert.state(authentication != null, "Access forbidden: not authenticated");

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Assert.state(principal != null, "Principal must not be null");
        Assert.state(principal instanceof Token, "Unexpected principal type");

        return (Token) principal;
    }


}
