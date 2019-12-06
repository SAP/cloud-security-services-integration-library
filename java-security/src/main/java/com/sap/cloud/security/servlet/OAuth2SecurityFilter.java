package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OAuth2SecurityFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(OAuth2SecurityFilter.class);
	private final TokenExtractor tokenExtractor;
	private Validator<Token> tokenValidator;

	public OAuth2SecurityFilter() {
		this((OAuth2TokenKeyServiceWithCache) null, null);
	}

	/**
	 * In case you want to use your own Rest client or you want to configure/manage
	 * the cache by your own you can provide your own implementations of
	 * {@link OAuth2TokenKeyServiceWithCache} and
	 * {@link OAuth2TokenKeyServiceWithCache}.
	 *
	 * @param tokenKeyService
	 *            the service that requests the token keys (jwks) if not yet cached.
	 * @param oidcConfigurationService
	 *            the service that requests the open-id provider configuration if
	 *            not yet cached.
	 */
	public OAuth2SecurityFilter(OAuth2TokenKeyServiceWithCache tokenKeyService,
			OidcConfigurationServiceWithCache oidcConfigurationService) {
		tokenExtractor = authorizationHeader -> new XsuaaToken(authorizationHeader);
		tokenValidator = JwtValidatorBuilder
				.getInstance(getXsuaaServiceConfiguration())
				.withOAuth2TokenKeyService(tokenKeyService)
				.withOidcConfigurationService(oidcConfigurationService)
				.configureAnotherServiceInstance(getOtherXsuaaServiceConfiguration())
				.build();
	}

	OAuth2SecurityFilter(TokenExtractor tokenExtractor, Validator<Token> tokenValidator) {
		this.tokenExtractor = tokenExtractor;
		this.tokenValidator = tokenValidator;
	}

	@Override
	public void init(FilterConfig filterConfig) {
		// nothing to do
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) {
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			HttpServletResponse httpResponse = (HttpServletResponse) response;
			String authorizationHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
			if (headerIsAvailable(authorizationHeader)) {
				try {
					Token token = tokenExtractor.fromAuthorizationHeader(authorizationHeader);
					if (token.getService() != Service.XSUAA) {
						logger.info("The token of service {} is not validated by {}.", token.getService(), getClass());
						return;
					}
					ValidationResult result = tokenValidator.validate(token);
					if (result.isValid()) {
						SecurityContext.setToken(token);
						filterChain.doFilter(request, response);
					} else {
						unauthorized(httpResponse, "Error during token validation: " + result.getErrorDescription());
					}
				} catch (Exception e) {
					unauthorized(httpResponse, "Unexpected error occurred: " + e.getMessage());
				}
			} else {
				unauthorized(httpResponse, "Authorization header is missing");
			}
		}
	}

	@Override
	public void destroy() {
		SecurityContext.clearToken();
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

	private void unauthorized(HttpServletResponse httpResponse, String message) {
		logger.warn(message);
		httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	}

	private boolean headerIsAvailable(String authorizationHeader) {
		return authorizationHeader != null && !authorizationHeader.isEmpty();
	}

	interface TokenExtractor {
		Token fromAuthorizationHeader(String authorizationHeader);
	}

}
