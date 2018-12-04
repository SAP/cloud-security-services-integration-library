package com.sap.xs2.security.container;

import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityContext {
	/**
	 * Obtain the UserInfo object from the Spring SecurityContext
	 * 
	 * @return UserInfo object
	 * @throws UserInfoException
	 */
	static public UserInfo getUserInfo() throws UserInfoException {
		if (SecurityContextHolder.getContext().getAuthentication() != null) {
			if (SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof UserInfo) {
				return (UserInfo) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
			}
			else
			{
				throw new UserInfoException("Unexpected principal type");
			}
		}
		else
		{
			throw new UserInfoException("Not authenticated");
		}
	}

}
