package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.ScopeConverter;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaScopeConverter;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Objects;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE_ENHANCER;

public class XsuaaTokenAuthenticator extends AbstractTokenAuthenticator {

	private static final Logger LOGGER = LoggerFactory.getLogger(XsuaaTokenAuthenticator.class);
	private static final String IAS_XSUAA_ENABLED = "IAS_XSUAA_XCHANGE_ENABLED";
	private IasXsuaaExchangeBroker exchangeBroker;

	public XsuaaTokenAuthenticator() {
	}

	public XsuaaTokenAuthenticator(IasXsuaaExchangeBroker exchangeBroker) {
		this.exchangeBroker = exchangeBroker;
	}

	@Override
	public Token extractFromHeader(String authorizationHeader) {
		return new XsuaaToken(authorizationHeader)
				.withScopeConverter(getScopeConverter());
	}

	@Override
	protected OAuth2ServiceConfiguration getServiceConfiguration() {
		OAuth2ServiceConfiguration config = serviceConfiguration != null ? serviceConfiguration
				: Environments.getCurrent().getXsuaaConfiguration();
		if (config == null) {
			throw new IllegalStateException("There must be a service configuration.");
		}
		return config;
	}

	@Nullable
	@Override
	protected OAuth2ServiceConfiguration getOtherServiceConfiguration() {
		return Environments.getCurrent().getXsuaaConfigurationForTokenExchange();
	}

	@Override
	protected TokenAuthenticationResult authenticated(Token token) {
		Collection<String> translatedScopes = getScopeConverter()
				.convert(((XsuaaToken) token).getScopes());
		return TokenAuthenticatorResult.createAuthenticated(translatedScopes, token);
	}

	@Override
	public TokenAuthenticationResult validateRequest(ServletRequest request, ServletResponse response) {
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			String authorizationHeader = httpRequest.getHeader(HttpHeaders.AUTHORIZATION);
			if (headerIsAvailable(authorizationHeader)) {
				try {
					Token token = extractFromHeader(authorizationHeader);
					if (isIasXsuaaXchangeEnabled() && !isXsuaaToken(token)) {
						token = new XsuaaToken(Objects.requireNonNull(
								exchangeBroker.doIasToXsuaaXchange(httpClient, token, serviceConfiguration),
								"IasXsuaaExchangeBroker is not provided"));
					}
					return tokenValidationResult(token);
				} catch (Exception e) {
					return unauthenticated("Unexpected error occurred: " + e.getMessage());
				}
			} else {
				return unauthenticated("Authorization header is missing.");
			}
		}
		return TokenAuthenticatorResult.createUnauthenticated("Could not process request " + request);
	}

	private ScopeConverter getScopeConverter() {
		return new XsuaaScopeConverter(
				getServiceConfiguration().getProperty(CFConstants.XSUAA.APP_ID));
	}

	/**
	 * Verifies if the provided token is Xsuaa token
	 *
	 * @exception NullPointerException
	 *                if the external attribute enhancer(enhancer) value is missing
	 *                but the external attribute(ext_atr) claim is present
	 * @param token
	 *            Token to be checked
	 * @return true if provided token is a XSUAA token
	 */
	private boolean isXsuaaToken(Token token) {
		JsonObject externalAttributeClaim = token.getClaimAsJsonObject(EXTERNAL_ATTRIBUTE);

		if (externalAttributeClaim != null) {
			String externalAttributeValue = externalAttributeClaim.getAsString(EXTERNAL_ATTRIBUTE_ENHANCER);
			LOGGER.debug("Token attributes claims: {}: {}", EXTERNAL_ATTRIBUTE, externalAttributeClaim);
			return Objects.requireNonNull(externalAttributeValue, "enhancer is missing").equalsIgnoreCase("xsuaa");
		} else {
			LOGGER.debug("Token is not Xsuaa token: {}", token.getTokenValue());
			return false;
		}
	}

	/**
	 * Checks value of environment variable 'IAS_XSUAA_XCHANGE_ENABLED'. This value
	 * determines, whether token exchange between IAS and XSUAA is enabled. If
	 * IAS_XSUAA_XCHANGE_ENABLED is not provided or with an empty value or with
	 * value = false, then token exchange is disabled. Any other values are
	 * interpreted as true.
	 *
	 * @return returns true if exchange is enabled and false if disabled
	 */

	private boolean isIasXsuaaXchangeEnabled() {
		String isEnabled = System.getenv(IAS_XSUAA_ENABLED);
		LOGGER.debug("System environment variable {} is set to {}", IAS_XSUAA_ENABLED, isEnabled);
		return isEnabled != null && !isEnabled.equalsIgnoreCase("false");
	}
}
