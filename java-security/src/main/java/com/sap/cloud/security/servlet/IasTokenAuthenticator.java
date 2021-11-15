/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.x509.X509CertExtractor;

import javax.annotation.Nullable;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class IasTokenAuthenticator extends AbstractTokenAuthenticator {

	private final X509CertExtractor x509CertExtractor = X509CertExtractor.create();

	@Override
	public Token extractFromHeader(String authorizationHeader) {
		return new SapIdToken(authorizationHeader);
	}

	@Override
	public TokenAuthenticationResult validateRequest(ServletRequest request, ServletResponse response) {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		SecurityContext.setClientCertificate(x509CertExtractor.getClientCertificate(httpRequest));
		return super.validateRequest(request, response);
	}

	@Override
	protected OAuth2ServiceConfiguration getServiceConfiguration() {
		OAuth2ServiceConfiguration config = serviceConfiguration != null ? serviceConfiguration
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

	@Override
	final Validator<Token> getOrCreateTokenValidator() {
		if (this.tokenValidator == null) {
			JwtValidatorBuilder jwtValidatorBuilder = getJwtValidatorBuilder();
			this.tokenValidator = jwtValidatorBuilder.build();
		}
		return this.tokenValidator;
	}
}
