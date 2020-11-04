package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.token.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
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
 */
public class SpringSecurityContext {

	private SpringSecurityContext() {
	}

	/**
	 * Returns the token using {@link SecurityContextHolder}.
	 *
	 *
	 * @return the token or <code>null</code> if {@link SecurityContext} is empty or
	 *         does not contain a token of this type.
	 */
	@Nullable
	public static Token getToken() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (Objects.nonNull(authentication) && authentication.isAuthenticated() &&
				authentication.getDetails() instanceof OAuth2AuthenticationDetails) {
			OAuth2AuthenticationDetails authDetails = (OAuth2AuthenticationDetails) authentication.getDetails();
			String tokenValue = authDetails.getTokenValue();
			AbstractToken xsuaaToken = new XsuaaTokenWithGrantedAuthorities(tokenValue, authentication.getAuthorities());
			if (xsuaaToken.isXsuaaToken()) {
				return xsuaaToken;
			}
			return new SapIdToken(tokenValue);
		}
		return null;
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
