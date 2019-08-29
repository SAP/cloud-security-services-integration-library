package com.sap.xs2.security.container;

import com.sap.cloud.security.xsuaa.extractor.AuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.extractor.LocalAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.token.SpringSecurityContext;
import com.sap.cloud.security.xsuaa.token.Token;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * As part of this Spring xsuaa library, we need to get rid of
 * {@code com.sap.xs2.security.container} package. It will be removed with
 * version {@code 2.0.0}
 *
 * @deprecated use {@link SpringSecurityContext} class instead.
 */
@Deprecated
public class SecurityContext {
	/**
	 * Obtain the UserInfo object from the Spring Security Context
	 *
	 * @return UserInfo object
	 * @throws UserInfoException
	 *             in case of error
	 * @deprecated use {@link #getToken()} instead.
	 */
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
	 * Obtain the Token object from the Spring Security Context
	 *
	 * @return Token object
	 * @throws AccessDeniedException
	 *             in case there is no token, user is not authenticated
	 *             <p>
	 *             Note: This method is introduced with xsuaa spring client lib.
	 * @deprecated method is moved to {@link SpringSecurityContext#getToken()}
	 */
	static public Token getToken() {
		return SpringSecurityContext.getToken();
	}

	/**
	 * Initializes the Spring Security Context and extracts the authorities.
	 *
	 * @param appId
	 *            the application id e.g. myXsAppname!t123
	 * @param token
	 *            the jwt token
	 * @param extractLocalScopesOnly
	 *            true when {@link Token#getAuthorities()} should only extract local
	 *            scopes. Local scopes means that non-application specific scopes
	 *            are filtered out and scopes are returned without appId prefix,
	 *            e.g. "Display".
	 * @deprecated use method
	 *             {@link SpringSecurityContext#init(String, JwtDecoder, AuthoritiesExtractor)}
	 *             instead
	 */
	static public void init(String appId, Jwt token, boolean extractLocalScopesOnly) {
		TokenAuthenticationConverter authenticationConverter = new TokenAuthenticationConverter(
				new LocalAuthoritiesExtractor(appId));
		Authentication authentication = authenticationConverter.convert(token);

		SecurityContextHolder.createEmptyContext();
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	/**
	 * Cleans up the Spring Security Context and release thread locals for Garbage
	 * Collector to avoid memory leaks resources.
	 *
	 * @deprecated method is moved to {@link SpringSecurityContext#clear()}
	 */
	static public void clear() {
		SpringSecurityContext.clear();
	}
}