package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class DefaultTokenAuthenticator implements TokenAuthenticator {

	private static final Logger logger = LoggerFactory.getLogger(DefaultTokenAuthenticator.class);
	private final TokenExtractor tokenExtractor;
	private Validator<Token> tokenValidator;

	private OAuth2TokenKeyServiceWithCache tokenKeyService;
	private OidcConfigurationServiceWithCache oidcConfigurationService;

	public DefaultTokenAuthenticator(OAuth2TokenKeyServiceWithCache tokenKeyService,
			OidcConfigurationServiceWithCache oidcConfigurationService) {
		this.tokenKeyService = tokenKeyService;
		this.oidcConfigurationService = oidcConfigurationService;
		tokenExtractor = new DefaultTokenExtractor();
	}

	public DefaultTokenAuthenticator() {
		// TODO 12.12.19 c5295400: correct default?
		tokenKeyService = OAuth2TokenKeyServiceWithCache.getInstance();
		oidcConfigurationService = OidcConfigurationServiceWithCache.getInstance();
		tokenExtractor = new DefaultTokenExtractor();
	}

	DefaultTokenAuthenticator(TokenExtractor tokenExtractor, Validator<Token> tokenValidator) {
		this.tokenExtractor = tokenExtractor;
		this.tokenValidator = tokenValidator;
	}

	@Override
	public TokenAuthenticationResult validateRequest(ServletRequest request, ServletResponse response) {
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			String authorizationHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
			if (headerIsAvailable(authorizationHeader)) {
				try {
					Token token = getTokenExtractor().from(authorizationHeader);
					// if (token.getService() != Service.XSUAA) {
					// logger.info("The token of service {} is not validated by {}.",
					// token.getService(), getClass());
					// return unauthenticated(httpResponse, "Error during token validation: " +
					// result.getErrorDescription());
					// }
					ValidationResult result = getOrCreateTokenValidator().validate(token);
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

	// TODO 19.12.19 c5295400: Xsuaa/Ias sub classes instead
	public class DefaultTokenExtractor implements TokenExtractor {
		@Override
		public Token from(String authorizationHeader) {
			if (Environments.getCurrent().getXsuaaConfiguration() != null) {
				return new XsuaaToken(authorizationHeader,
						Environments.getCurrent().getXsuaaConfiguration().getProperty(CFConstants.XSUAA.APP_ID));
			}
			return new IasToken(authorizationHeader);
		}
	}

	@Override
	public TokenExtractor getTokenExtractor() {
		return tokenExtractor;
	}

	private TokenAuthenticationResult unauthenticated(HttpServletResponse httpResponse, String message) {
		try {
			httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		} catch (IOException e) {
			logger.error("Could not send unauthenticated response!", e);
		}
		return TokenAuthenticationResult.createUnauthenticated(message);
	}

	private TokenAuthenticationResult createAuthentication(Token token) {
		if (token instanceof XsuaaToken) {
			List<String> scopes = ((XsuaaToken) token).getScopes();
			List<String> translatedScopes = new ScopeTranslator().translateToLocalScope(scopes);
			return TokenAuthenticationResult.createAuthenticated(token.getPrincipal(), translatedScopes, token);
		}
		return TokenAuthenticationResult.createAuthenticated(token.getPrincipal(), new ArrayList<>(), token);
	}

	protected Validator<Token> getOrCreateTokenValidator() {
		if (tokenValidator == null) {
			tokenValidator = JwtValidatorBuilder
					.getInstance(Environments.getCurrent().getXsuaaConfiguration())
					.withOAuth2TokenKeyService(tokenKeyService)
					.withOidcConfigurationService(oidcConfigurationService)
					.configureAnotherServiceInstance(getOtherXsuaaServiceConfiguration())
					.build();
		}
		return tokenValidator;
	}

	@Nullable
	private OAuth2ServiceConfiguration getOtherXsuaaServiceConfiguration() {
		if (Environments.getCurrent().getNumberOfXsuaaConfigurations() > 1) {
			return Environments.getCurrent().getXsuaaConfigurationForTokenExchange();
		}
		return null;
	}

	private boolean headerIsAvailable(String authorizationHeader) {
		return authorizationHeader != null && !authorizationHeader.isEmpty();
	}

}
