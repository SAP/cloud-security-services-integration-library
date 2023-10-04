/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token;

import com.sap.cloud.security.spring.token.authentication.HybridJwtDecoder;
import com.sap.cloud.security.spring.token.authentication.XsuaaTokenAuthorizationConverter;
import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.Token;
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
 * <p>
 * It uses the {@link SecurityContextHolder} to access Spring's
 * {@link SecurityContext} and can therefore used also in context of
 * asynchronous threads.
 */
public class SpringSecurityContext {

	private SpringSecurityContext() {
	}

	/**
	 * Obtain the Token object from {@link SecurityContextHolder}.
	 *
	 * @return Token instance or <code>null</code> if {@link SecurityContext} is
	 *         empty or does not contain a token of this type.
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
				"Access forbidden: SecurityContextHolder does not contain a principal of type 'Token'. Found instead a principal of type " + principal.getClass());
	}

	/**
	 * Obtain the Access Token from xsuaa service from
	 * {@link SecurityContextHolder}.
	 *
	 * @return AccessToken instance or <code>null</code> if {@link SecurityContext}
	 *         is empty or does not contain a token of this type.
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
	 * @param authConverter
	 *            the authorization converter of type
	 *            {@code Converter<Jwt, AbstractAuthenticationToken>} e.g.
	 *            {@link XsuaaTokenAuthorizationConverter}
	 */
	public static void init(String encodedToken, JwtDecoder jwtDecoder,
			Converter<Jwt, AbstractAuthenticationToken> authConverter) {
		Assert.isInstanceOf(HybridJwtDecoder.class, jwtDecoder,
				"Passed JwtDecoder instance must be of type 'HybridJwtDecoder'");
		Assert.notNull(authConverter,
				"Passed converter must not be null");
		Jwt jwtToken = jwtDecoder.decode(encodedToken);

		Authentication authentication = authConverter.convert(jwtToken);

		SecurityContextHolder.createEmptyContext();
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

}
