/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.x509.X509Certificate;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Objects;

import static com.sap.cloud.security.servlet.TokenAuthenticatorResult.createUnauthenticated;

public class XsuaaTokenAuthenticator extends AbstractTokenAuthenticator {

	private static final Logger LOGGER = LoggerFactory.getLogger(XsuaaTokenAuthenticator.class);
	private static final String IAS_XSUAA_ENABLED = "IAS_XSUAA_XCHANGE_ENABLED";
	private IasXsuaaExchangeBroker exchangeBroker;

	public XsuaaTokenAuthenticator() {
		serviceConfiguration = Environments.getCurrent().getXsuaaConfiguration();
		httpClient = HttpClientFactory
				.create(serviceConfiguration != null ? serviceConfiguration.getClientIdentity() : null);
		buildDependencies();
	}

	XsuaaTokenAuthenticator(IasXsuaaExchangeBroker exchangeBroker) {
		this.exchangeBroker = exchangeBroker;
	}

	@Override
	public AbstractTokenAuthenticator withServiceConfiguration(OAuth2ServiceConfiguration serviceConfiguration) {
		super.withServiceConfiguration(serviceConfiguration);
		buildDependencies();
		return this;
	}

	@Override
	public AbstractTokenAuthenticator withHttpClient(CloseableHttpClient httpClient) {
		super.withHttpClient(httpClient);
		buildDependencies();
		return this;
	}

	/**
	 * There are some setters, which impacts the setup of dependencies, that needs
	 * to be updated.
	 */
	private void buildDependencies() {
		if (serviceConfiguration != null && httpClient != null && isIasXsuaaXchangeEnabled()) {
			this.exchangeBroker = IasXsuaaExchangeBroker.build(this.serviceConfiguration,
					new DefaultOAuth2TokenService(httpClient));
		}
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
					SecurityContext.setClientCertificate(X509Certificate
							.newCertificate(getClientCertificate(httpRequest)));
					Token token = Token.create(authorizationHeader);
					if (token.getService() == Service.IAS) {
						if (exchangeBroker == null) {
							return unauthenticated("IAS token validation is not supported: "
									+ (isIasXsuaaXchangeEnabled() ? "setup is malicious."
											: "no token exchange enabled."));
						} else if (isIasXsuaaXchangeEnabled()) {
							LOGGER.debug("Received {} token", token.getService());
							token = new XsuaaToken(Objects.requireNonNull(
									exchangeBroker.resolve(token),
									"IasXsuaaExchangeBroker is not provided"))
											.withScopeConverter(getScopeConverter());
						}
					}
					return tokenValidationResult(token);
				} catch (Exception e) {
					return createUnauthenticated("Unexpected error occurred: " + e.getMessage());
				}
			} else {
				return createUnauthenticated("Authorization header is missing.");
			}
		}
		return createUnauthenticated("Could not process request " + request);
	}

	private ScopeConverter getScopeConverter() {
		return new XsuaaScopeConverter(
				getServiceConfiguration().getProperty(ServiceConstants.XSUAA.APP_ID));
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
