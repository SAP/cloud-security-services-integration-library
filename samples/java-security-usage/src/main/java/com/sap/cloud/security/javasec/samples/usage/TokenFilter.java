package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.TokenValidatorBuilder;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebFilter(urlPatterns = "/*")
public class TokenFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(TokenFilter.class);
	private final TokenExtractor tokenExtractor;
	private Validator<Token> tokenValidator;


	public TokenFilter() {
		tokenExtractor = authorizationHeader -> new XsuaaToken(authorizationHeader);
	}

	TokenFilter(TokenExtractor tokenExtractor, Validator<Token> tokenValidator) {
		this.tokenExtractor = tokenExtractor;
		this.tokenValidator = tokenValidator;
	}

	@Override public void init(FilterConfig filterConfig) {
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
			tokenValidator = TokenValidatorBuilder
					.createFor(getXsuaaServiceConfiguration())
					.configureAnotherServiceInstance(getOtherXsuaaServiceConfiguration())
					.build();
		}
		return tokenValidator.validate(token);
	}

	private OAuth2ServiceConfiguration getXsuaaServiceConfiguration() {
		return Environments.getCurrentEnvironment().getXsuaaServiceConfiguration();
	}

	@Nullable
	private OAuth2ServiceConfiguration getOtherXsuaaServiceConfiguration() {
		if (Environments.getCurrentEnvironment().getNumberOfXsuaaServices() > 1) {
			return Environments.getCurrentEnvironment().getXsuaaServiceConfigurationForTokenExchange();
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
