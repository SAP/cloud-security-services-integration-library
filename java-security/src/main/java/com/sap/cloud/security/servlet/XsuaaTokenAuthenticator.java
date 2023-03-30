/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.x509.X509Certificate;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;

import javax.annotation.Nullable;
import java.util.Collection;

import static com.sap.cloud.security.servlet.TokenAuthenticatorResult.createUnauthenticated;

public class XsuaaTokenAuthenticator extends AbstractTokenAuthenticator {


	public XsuaaTokenAuthenticator() {
		serviceConfiguration = Environments.getCurrent().getXsuaaConfiguration();
		httpClient = HttpClientFactory
				.create(serviceConfiguration != null ? serviceConfiguration.getClientIdentity() : null);
	}

	@Override
	public AbstractTokenAuthenticator withServiceConfiguration(OAuth2ServiceConfiguration serviceConfiguration) {
		super.withServiceConfiguration(serviceConfiguration);
		return this;
	}

	@Override
	public AbstractTokenAuthenticator withHttpClient(CloseableHttpClient httpClient) {
		super.withHttpClient(httpClient);
		return this;
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
}
