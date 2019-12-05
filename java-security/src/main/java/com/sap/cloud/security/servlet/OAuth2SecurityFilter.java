package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebFilter(urlPatterns = "/*", filterName = "OAuth2SecurityFilter")
public class OAuth2SecurityFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(OAuth2SecurityFilter.class);
	private final TokenExtractor tokenExtractor;
	private OidcConfigurationService oidcConfigurationService = null;
	private Validator<Token> tokenValidator;

	public OAuth2SecurityFilter() {
		this.tokenExtractor = authorizationHeader -> new XsuaaToken(authorizationHeader);
	}

	public OAuth2SecurityFilter(OidcConfigurationService oidcConfigurationService) {
		this.tokenExtractor = authorizationHeader -> new XsuaaToken(authorizationHeader);
		this.oidcConfigurationService = oidcConfigurationService;
	}

	OAuth2SecurityFilter(TokenExtractor tokenExtractor, Validator<Token> tokenValidator) {
		this.tokenExtractor = tokenExtractor;
		this.tokenValidator = tokenValidator;
	}

	@Override
	public void init(FilterConfig filterConfig) {
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
					ValidationResult result = validateToken(token);
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

	private ValidationResult validateToken(Token token) {
		if (tokenValidator == null) {
			tokenValidator = JwtValidatorBuilder
					.getInstance(getXsuaaServiceConfiguration())
					.withOidcConfigurationService(oidcConfigurationService)
					.configureAnotherServiceInstance(getOtherXsuaaServiceConfiguration())
					.build();
		}
		return tokenValidator.validate(token);
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
