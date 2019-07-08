package com.sap.xs2.security.container;

import com.sap.cloud.security.xsuaa.extractor.AuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.extractor.LocalAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.token.Token;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.Assert;

public class SecurityContext {
	/**
	 * Obtain the UserInfo object from the Spring SecurityContext
	 *
	 * @return UserInfo object
	 * @throws UserInfoException
	 *             in case of error
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
	 * @throws AccessDeniedException
	 *             in case there is no token, user is not authenticated
	 */
	static public Token getToken() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication == null) {
			throw new AccessDeniedException("Access forbidden: not authenticated");
		}

		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		Assert.state(principal != null, "Principal must not be null");
		Assert.state(principal instanceof Token, "Unexpected principal type");

		return (Token) principal;
	}

	/**
	 * Initializes the Spring SecurityContext and extracts the authorities.
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
	 */
	static public void init(String appId, Jwt token, boolean extractLocalScopesOnly) {
		TokenAuthenticationConverter authenticationConverter = new TokenAuthenticationConverter(
				new LocalAuthoritiesExtractor(appId));
		Authentication authentication = authenticationConverter.convert(token);

		SecurityContextHolder.createEmptyContext();
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	/**
	 * Initializes the Spring SecurityContext and extracts the authorities. With
	 * version 1.5.0 you can configure your own {@link AuthoritiesExtractor} to
	 * specify how to extract the authorities.
	 *
	 * @param encodedJwtToken
	 *            the jwt token that is decoded with the given JwtDecoder
	 * @param jwtDecoder
	 *            hte decoder
	 * @param authoritiesExtractor
	 *            the extractor used to turn Jwt scopes into Spring Security
	 *            authorities.
	 */
	static public void init(String encodedJwtToken, JwtDecoder jwtDecoder, AuthoritiesExtractor authoritiesExtractor) {
		Jwt jwtToken = jwtDecoder.decode(encodedJwtToken);

		TokenAuthenticationConverter authenticationConverter = new TokenAuthenticationConverter(authoritiesExtractor);
		Authentication authentication = authenticationConverter.convert(jwtToken);

		SecurityContextHolder.createEmptyContext();
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	static public void clear() {
		SecurityContextHolder.clearContext();
	}
}