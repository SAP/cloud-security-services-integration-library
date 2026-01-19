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
import com.sap.cloud.security.x509.X509Certificate;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import javax.annotation.Nullable;

public class IasTokenAuthenticator extends AbstractTokenAuthenticator {

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
    return super.validateRequest(request, response);
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
