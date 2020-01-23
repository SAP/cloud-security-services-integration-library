package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.adapter.xs.XSUserInfoAdapter;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.xsa.security.container.XSUserInfoException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

public class XSUserInfoSpringAdapter extends XSUserInfoAdapter {

    public XSUserInfoSpringAdapter(Token xsuaaToken) throws XSUserInfoException {
        super(xsuaaToken);
    }

    public XSUserInfoSpringAdapter() throws XSUserInfoException {
        super(readFromSpringSecurityContext());
    }

    private static Token readFromSpringSecurityContext() throws XSUserInfoException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            throw new XSUserInfoException("User not authenticated (Spring Security Context is empty)");
        }
        if (!(auth.getDetails() instanceof OAuth2AuthenticationDetails)) {
            throw new XSUserInfoException("token needs to be an instance of XsuaaToken.");
        }
        String tokenValue = ((OAuth2AuthenticationDetails) auth.getDetails()).getTokenValue();
        return new XsuaaToken(tokenValue);
    }
}
