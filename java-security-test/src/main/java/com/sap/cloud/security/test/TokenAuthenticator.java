package com.sap.cloud.security.test;

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
import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.DefaultUserIdentity;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.server.Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.security.auth.Subject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

class TokenAuthenticator implements Authenticator {

	private static final Logger logger = LoggerFactory.getLogger(TokenAuthenticator.class);
	private final TokenExtractor tokenExtractor;
	private Validator<Token> tokenValidator;

	private OAuth2TokenKeyServiceWithCache tokenKeyService;
	private OidcConfigurationServiceWithCache oidcConfigurationService;

	// TODO 12.12.19 c5295400: use this constructor from rule
	public TokenAuthenticator(OAuth2TokenKeyServiceWithCache tokenKeyService,
			OidcConfigurationServiceWithCache oidcConfigurationService) {
		this.tokenKeyService = tokenKeyService;
		this.oidcConfigurationService = oidcConfigurationService;
		tokenExtractor = new DefaultTokenExtractor();
	}

	public TokenAuthenticator() {
		// TODO 12.12.19 c5295400: correct default?
		tokenKeyService = OAuth2TokenKeyServiceWithCache.getInstance();
		oidcConfigurationService = OidcConfigurationServiceWithCache.getInstance();
		tokenExtractor = new DefaultTokenExtractor();
	}

	@Override
	public void setConfiguration(AuthConfiguration configuration) {
	}

	@Override
	public String getAuthMethod() {
		return "Token";
	}

	@Override
	public void prepareRequest(ServletRequest request) {
		request.getServletContext();
	}

	@Override
	public Authentication validateRequest(ServletRequest request, ServletResponse response, boolean mandatory) {
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			String authorizationHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
			if (headerIsAvailable(authorizationHeader)) {
				try {
					Token token = tokenExtractor.from(authorizationHeader);
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
		return Authentication.NOT_CHECKED;
	}

	@Override
	public boolean secureResponse(ServletRequest request, ServletResponse response, boolean mandatory,
			Authentication.User validatedUser) {
		return true;
	}

	private Authentication unauthenticated(HttpServletResponse httpResponse, String message) {
		try {
			httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		logger.warn("Could not authenticate user!");
		return Authentication.UNAUTHENTICATED;
	}

	private void unauthorized(HttpServletResponse httpResponse, String message) {
		logger.warn(message);
		httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	}

	private Authentication createAuthentication(Token token) {
		Principal principal = token.getPrincipal();
		Set<Principal> principals = new HashSet<>();
		principals.add(principal);
		Subject subject = new Subject(true, principals, new HashSet<>(), new HashSet<>());
		if (token instanceof XsuaaToken) {
			String[] scopes = ((XsuaaToken) token).getScopes().toArray(new String[0]);
			return new UserAuthentication(getAuthMethod(), new DefaultUserIdentity(subject, principal, scopes));
		}
		return new UserAuthentication(getAuthMethod(), new DefaultUserIdentity(subject, principal, new String[0]));
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

	private OAuth2ServiceConfiguration getXsuaaServiceConfiguration() {
		return Environments.getCurrent().getXsuaaConfiguration();
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

	public interface TokenExtractor {
		Token from(String authorizationHeader);
	}

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

}
