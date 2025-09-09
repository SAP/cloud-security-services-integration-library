/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.context.ContextExtensionsRegistry;
import com.sap.cloud.security.x509.X509Certificate;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IasTokenAuthenticator extends AbstractTokenAuthenticator {
  private static final Logger LOG = LoggerFactory.getLogger(IasTokenAuthenticator.class);
  private ContextExtensionsRegistry contextExtensionsRegistry;

  public IasTokenAuthenticator withExtensionsRegistry(final ContextExtensionsRegistry registry) {
    this.contextExtensionsRegistry = registry;
    return this;
  }

  @Override
  public Token extractFromHeader(final String authorizationHeader) {
		return new SapIdToken(authorizationHeader);
	}

  @Override
  public TokenAuthenticationResult validateRequest(
      final ServletRequest request, final ServletResponse response) {
    final HttpServletRequest httpRequest = (HttpServletRequest) request;
    SecurityContext.setClientCertificate(
        X509Certificate.newCertificate(getClientCertificate(httpRequest)));
    final TokenAuthenticationResult validationResult = super.validateRequest(request, response);
    if (validationResult.isAuthenticated()) {
      if (contextExtensionsRegistry != null) {
        try {
          contextExtensionsRegistry.applyAll();
        } catch (final Exception e) {
          LOG.warn("Security context extension failed", e);
        }
        return TokenAuthenticatorResult.createAuthenticated(
            Collections.emptyList(), SecurityContext.getToken());
      }
    }
    return validationResult;
  }

	@Override
	protected OAuth2ServiceConfiguration getServiceConfiguration() {
    final OAuth2ServiceConfiguration config =
        serviceConfiguration != null
            ? serviceConfiguration
            : Environments.getCurrent().getIasConfiguration();
		if (config == null) {
			throw new IllegalStateException("There must be a service configuration.");
		}
		return config;
	}

	@Nullable
	@Override
	protected OAuth2ServiceConfiguration getOtherServiceConfiguration() {
		return null;
	}
}
