package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.Assertions;

import javax.annotation.Nullable;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class TokenAuthenticationResult {

	private final Collection<String> scopes;
	private final Principal principal;
	private final Token token;
	private final String errorMessage;

	private TokenAuthenticationResult(Principal principal, Collection<String> scopes, Token token) {
		this.principal = principal;
		this.token = token;
		this.scopes = scopes;
		this.errorMessage = "";
	}

	private TokenAuthenticationResult(String errorMessage) {
		this.principal = null;
		this.token = null;
		this.scopes = new ArrayList<>();
		this.errorMessage = errorMessage;
	}

	public static final TokenAuthenticationResult createUnauthenticated(String errorMessage) {
		Assertions.assertHasText(errorMessage, "Message must contain text");
		return new TokenAuthenticationResult(errorMessage);
	}

	public static TokenAuthenticationResult createAuthenticated(Principal principal, List<String> scopes, Token token) {
		return new TokenAuthenticationResult(principal, scopes, token);
	}

	@Nullable
	public Token getToken() {
		return token;
	}

	@Nullable
	public Principal getPrincipal() {
		return principal;
	}

	public Collection<String> getScopes() {
		return scopes;
	}

	public boolean isAuthenticated() {
		return errorMessage.isEmpty();
	}

	public String getErrorMessage() {
		return errorMessage;
	}
}
