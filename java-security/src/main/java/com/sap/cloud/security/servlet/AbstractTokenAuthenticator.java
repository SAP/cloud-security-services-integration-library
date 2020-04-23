package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationListener;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public abstract class AbstractTokenAuthenticator implements TokenAuthenticator {

	private static final Logger logger = LoggerFactory.getLogger(AbstractTokenAuthenticator.class);
	private final List<ValidationListener> validationListeners = new ArrayList<>();
	private Validator<Token> tokenValidator;
	protected CloseableHttpClient httpClient;
	protected OAuth2ServiceConfiguration serviceConfiguration;

	@Override
	public TokenAuthenticationResult validateRequest(ServletRequest request, ServletResponse response) {
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			String authorizationHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
			if (headerIsAvailable(authorizationHeader)) {
				try {
					Token token = extractFromHeader(authorizationHeader);
					ValidationResult result = getOrCreateTokenValidator().validate(token);
					if (result.isValid()) {
						SecurityContext.setToken(token);
						return authenticated(token);
					} else {
						return unauthenticated("Error during token validation: " + result.getErrorDescription());
					}
				} catch (Exception e) {
					return unauthenticated("Unexpected error occurred: " + e.getMessage());
				}
			} else {
				return unauthenticated("Authorization header is missing.");
			}
		}
		return TokenAuthenticatorResult.createUnauthenticated("Could not process request " + request);
	}

	public AbstractTokenAuthenticator withHttpClient(CloseableHttpClient httpClient) {
		this.httpClient = httpClient;
		return this;
	}

	public AbstractTokenAuthenticator withServiceConfiguration(OAuth2ServiceConfiguration serviceConfiguration) {
		this.serviceConfiguration = serviceConfiguration;
		return this;
	}

	/**
	 * Adds the validation listener to the jwt validator that is being used by the
	 * authenticator to validate the tokens.
	 * 
	 * @param validationListener
	 *            the listener to be added.
	 * @return the authenticator instance
	 */
	public AbstractTokenAuthenticator withValidationListener(ValidationListener validationListener) {
		this.validationListeners.add(validationListener);
		return this;
	}

	/**
	 * Return configured service configuration or Environments.getCurrent() if not
	 * configured.
	 * 
	 * @return the actual service configuration
	 * @throws IllegalStateException
	 *             in case service configuration is null
	 */
	protected abstract OAuth2ServiceConfiguration getServiceConfiguration();

	/**
	 * Return other configured service configurations or null if not configured.
	 *
	 * @return the other service configuration or null
	 */
	@Nullable
	protected abstract OAuth2ServiceConfiguration getOtherServiceConfiguration();

	/**
	 * Extracts the {@link Token} from the authorization header.
	 *
	 * @param authorizationHeader
	 *            the value of the 'Authorization' request header
	 * @return the {@link Token} instance.
	 */
	protected abstract Token extractFromHeader(String authorizationHeader);

	private Validator<Token> getOrCreateTokenValidator() {
		if (tokenValidator == null) {
			JwtValidatorBuilder jwtValidatorBuilder = JwtValidatorBuilder.getInstance(getServiceConfiguration())
					.withHttpClient(httpClient);
			jwtValidatorBuilder.configureAnotherServiceInstance(getOtherServiceConfiguration());
			validationListeners.forEach(jwtValidatorBuilder::withValidatorListener);
			tokenValidator = jwtValidatorBuilder.build();
		}
		return tokenValidator;
	}

	private TokenAuthenticationResult unauthenticated(String message) {
		logger.warn("Request could not be authenticated: {}.", message);
		return TokenAuthenticatorResult.createUnauthenticated(message);
	}

	protected TokenAuthenticationResult authenticated(Token token) {
		return TokenAuthenticatorResult.createAuthenticated(Collections.emptyList(), token);
	}

	private boolean headerIsAvailable(String authorizationHeader) {
		return authorizationHeader != null && !authorizationHeader.isEmpty();
	}

}
