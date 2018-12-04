package com.sap.cloud.security.xsuaa.authentication;

import java.util.Objects;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;

import com.sap.cloud.security.xsuaa.api.TokenAccessFacade;
import com.sap.cloud.security.xsuaa.token.service.XsuaaUserAuthenticationInfo;
import com.sap.xsa.security.container.XSUserInfo;

@Component("tokenAccess")
public class SecurityContext implements TokenAccessFacade {

	@Override
	public XSUserInfo getUserInfo() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (Objects.nonNull(authentication) && authentication instanceof OAuth2Authentication) {
			OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;
			XsuaaUserAuthenticationInfo userAuthentication = (XsuaaUserAuthenticationInfo) oAuth2Authentication.getUserAuthentication();
			XSUserInfo userInfo = (XSUserInfo) userAuthentication.getPrincipal();
			return userInfo;
		}
		return null;
	}
 

}
