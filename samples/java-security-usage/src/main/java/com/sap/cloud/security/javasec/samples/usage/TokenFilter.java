package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.CombiningValidator;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TokenFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(TokenFilter.class);
	private final TokenExtractor tokenExtractor;
	private Validator<Token> tokenValidator;
	private OAuth2ServiceConfiguration oAuth2ServiceConfiguration;

	public TokenFilter() {
		tokenExtractor = (authorizationHeader) -> new TokenImpl(authorizationHeader);
	}

	TokenFilter(TokenExtractor tokenExtractor, Validator<Token> tokenValidator) {
		this.tokenExtractor = tokenExtractor;
		this.tokenValidator = tokenValidator;
	}

	private Validator<Token> getTokenValidator() {
		if (tokenValidator == null) {
			tokenValidator = CombiningValidator
					.builderFor(getXsuaaServiceConfiguration())
					.withOAuth2TokenKeyService((x) -> new JsonWebKeySet())
					.build();
		}
		return tokenValidator;
	}

	private OAuth2ServiceConfiguration getXsuaaServiceConfiguration() {
		if (oAuth2ServiceConfiguration == null) {
			oAuth2ServiceConfiguration = Environment.getInstance().getXsuaaServiceConfiguration();
		}
		return oAuth2ServiceConfiguration;
	}

	@Override
	public void init(FilterConfig filterConfig) {
		String configurationClass = filterConfig.getInitParameter("configuration-class");
		if (configurationClass != null) {
			try {
				oAuth2ServiceConfiguration = (OAuth2ServiceConfiguration) filterConfig.getServletContext()
						.getClassLoader()
						.loadClass(configurationClass)
						.newInstance();
			} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
				logger.error("Failed to load class {}, ", configurationClass, e);
			}
		}
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
					ValidationResult result = getTokenValidator().validate(token);
					if (result.isValid()) {
						SecurityContext.setToken(token);
						filterChain.doFilter(request, response);
					} else {
						unauthorized(httpResponse, "Error during token validation: " + result.getErrorDescription());
					}
				} catch (Exception e) {
					unauthorized(httpResponse, "Unexpected error occured: " + e.getMessage());
				}
			} else {
				unauthorized(httpResponse, "Authorization header is missing");
			}
		}
	}

	private void unauthorized(HttpServletResponse httpResponse, String message) {
		logger.error(message);
		httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	}

	private boolean headerIsAvailable(String authorizationHeader) {
		return authorizationHeader != null && !authorizationHeader.isEmpty();
	}

	@Override
	public void destroy() {
		SecurityContext.clearToken();
	}

	interface TokenExtractor {
		Token fromAuthorizationHeader(String authorizationHeader);
	}

}
