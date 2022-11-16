/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.token.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Objects;

/**
 * This is an alternative way of accessing jwt tokens of type {@link Token} or
 * {@link AccessToken} in context of an application using
 * spring-security-oauth2.
 *
 * It uses the {@link SecurityContextHolder} to access Spring's
 * {@link SecurityContext} and can therefore used also in context of
 * asynchronous threads.
 *
 * Use this class in case your application sets Spring's security context via
 * one of these libraries: <br>
 * <ol>
 * <li>@code{org.springframework.security.oauth:spring-security-oauth2} or</li>
 * <li>@code{com.sap.cloud.security.xsuaa:spring-xsuaa} client library.</li>
 * </ol>
 */
public class SpringSecurityContext {

	static final Logger LOGGER = LoggerFactory.getLogger(SpringSecurityContext.class);

	private SpringSecurityContext() {
	}

	/**
	 * Returns the token using {@link SecurityContextHolder}.
	 *
	 * @return the token or <code>null</code> if {@link SecurityContext} is empty or
	 *         does not contain a token of this type.
	 */
	@Nullable
	public static Token getToken() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (Objects.nonNull(authentication) && authentication.isAuthenticated()) {
			try {
				if (authentication.getDetails() != null && authentication.getDetails().getClass()
						.getName()
						.equals("org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails")) {
					LOGGER.debug("Try to fetch token from deprecated Springs Auth2 client library.");
					return getTokenFromDeprecatedLib(authentication);
				} else if (authentication.getPrincipal() == null) {
					return null; // no token available
				}
				String principalClass = authentication.getPrincipal().getClass().getName();
				LOGGER.debug("Try to fetch token from SecurityContextHolder.getPrincipal() of type {}.",
						authentication.getPrincipal().getClass().getName());
				if (principalClass.startsWith("com.sap.cloud.security.xsuaa.token.")) {
					return getSpringXsuaaToken(authentication);
				} else if (principalClass.startsWith("com.sap.cloud.security.token.")) {
					return (Token) authentication.getPrincipal();
				} else if (principalClass.startsWith("org.springframework.security.oauth2.core.oidc.user")) {
					return getSpringOidcIdToken(authentication);
				}
			} catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
				LOGGER.error("Does not yet support (Tokens of class: {})", authentication.getPrincipal().getClass());
			}
		} else {
			LOGGER.debug("Spring SecurityContextHolder does not contain a token which was authenticated ({})",
					authentication);
		}
		return null;
	}

	/**
	 * Returns the token using {@link SecurityContextHolder}.
	 *
	 * @return the token or <code>null</code> if {@link SecurityContext} is empty or
	 *         does not contain a token of this type.
	 */
	@Nullable
	static Token getTokenFromDeprecatedLib(Authentication authentication)
			throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		Method getTokenValue = authentication.getDetails().getClass().getMethod("getTokenValue");
		String encodedToken = (String) getTokenValue.invoke(authentication.getDetails());
		AbstractToken xsuaaToken = new XsuaaTokenWithGrantedAuthorities(encodedToken,
				authentication.getAuthorities());
		if (xsuaaToken.isXsuaaToken()) {
			return xsuaaToken;
		}
		return new SapIdToken(encodedToken);
	}

	static Token getSpringXsuaaToken(Authentication authentication)
			throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
		Method getAppToken = authentication.getPrincipal().getClass().getMethod("getAppToken");
		String encodedToken = (String) getAppToken.invoke(authentication.getPrincipal());
		return Token.create(encodedToken);
	}

	static Token getSpringOidcIdToken(Authentication authentication)
			throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		Method getIdToken = authentication.getPrincipal().getClass().getMethod("getIdToken");
		Object oidcToken = getIdToken.invoke(authentication.getPrincipal());
		Method getTokenValue = oidcToken.getClass().getMethod("getTokenValue");
		String encodedToken = (String) getTokenValue.invoke(oidcToken);
		return Token.create(encodedToken);
	}

	/**
	 * Returns the token using {@link SecurityContextHolder}.
	 *
	 *
	 * @return the token or <code>null</code> if {@link SecurityContext} is empty or
	 *         does not contain a token of this type.
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

	/**
	 * This class extends the {@link XsuaaToken} and takes the scopes from Spring
	 * {@link GrantedAuthority} to perform the {@link #hasLocalScope(String)} check.
	 * Therefore make sure that you've configured local scopes as authorities using
	 * {@link SAPOfflineTokenServicesCloud#setLocalScopeAsAuthorities(boolean)}.
	 */
	private static class XsuaaTokenWithGrantedAuthorities extends XsuaaToken {
		private final Collection<? extends GrantedAuthority> authorities;

		public XsuaaTokenWithGrantedAuthorities(String tokenValue,
				@Nullable Collection<? extends GrantedAuthority> authorities) {
			super(tokenValue);
			this.authorities = authorities;
		}

		@Override
		public boolean hasLocalScope(@Nonnull String scope) {
			return authorities.contains(new SimpleGrantedAuthority(scope));
		}
	}
}
