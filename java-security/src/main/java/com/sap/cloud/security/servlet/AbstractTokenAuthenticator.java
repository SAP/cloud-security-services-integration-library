package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.ScopeTranslator;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public abstract class AbstractTokenAuthenticator implements TokenAuthenticator {

	private static final Logger logger = LoggerFactory.getLogger(AbstractTokenAuthenticator.class);
	private Validator<Token> tokenValidator;


	@Override
	public TokenAuthenticationResult validateRequest(ServletRequest request, ServletResponse response) {
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			String authorizationHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
			if (headerIsAvailable(authorizationHeader)) {
				try {
					Token token = getTokenExtractor().from(authorizationHeader);
					ValidationResult result = createTokenValidator().validate(token);
					if (result.isValid()) {
						SecurityContext.setToken(token);
						return createAuthentication(token);
					} else {
						return unauthenticated(httpResponse,
								"Error during token validation: " + result.getErrorDescription());
					}
				} catch (Exception e) {
					return unauthenticated(httpResponse, "Unexpected error occurred: " + e.getMessage());
				}
			} else {
				return unauthenticated(httpResponse, "Authorization header is missing");
			}
		}
		return TokenAuthenticationResult.createUnauthenticated("Could not process request " + request);
	}

	protected abstract Validator<Token> createTokenValidator();

	protected Validator<Token> getOrCreateTokenValidator() {
		if (tokenValidator == null) {
			tokenValidator = createTokenValidator();
		}
		return tokenValidator;
	}

	private TokenAuthenticationResult unauthenticated(HttpServletResponse httpResponse, String message) {
		try {
			httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
		} catch (IOException e) {
			logger.error("Could not send unauthenticated response!", e);
		}
		return TokenAuthenticationResult.createUnauthenticated(message);
	}

	private TokenAuthenticationResult createAuthentication(Token token) {
		if (token instanceof XsuaaToken) {
			List<String> scopes = ((XsuaaToken) token).getScopes();
			List<String> translatedScopes = new ScopeTranslator().translateToLocalScope(scopes);
			return TokenAuthenticationResult.authenticated(translatedScopes, token);
		}
		return TokenAuthenticationResult.authenticated(new ArrayList<>(), token);
	}


	private boolean headerIsAvailable(String authorizationHeader) {
		return authorizationHeader != null && !authorizationHeader.isEmpty();
	}

}
