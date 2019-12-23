package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class XsuaaTokenAuthenticator extends AbstractTokenAuthenticator {

	private OAuth2TokenKeyServiceWithCache tokenKeyService;
	private OidcConfigurationServiceWithCache oidcConfigurationService;
	private final TokenExtractor xsuaaTokenExtractor = new XsuaaTokenExtractor();

	public XsuaaTokenAuthenticator() {
		this(OAuth2TokenKeyServiceWithCache.getInstance(), OidcConfigurationServiceWithCache.getInstance());
	}

	public XsuaaTokenAuthenticator(OAuth2TokenKeyServiceWithCache tokenKeyService,
			OidcConfigurationServiceWithCache oidcConfigurationService) {
		this.tokenKeyService = tokenKeyService;
		this.oidcConfigurationService = oidcConfigurationService;
	}

	@Override
	public TokenExtractor getTokenExtractor() {
		return xsuaaTokenExtractor;
	}

	@Override
	protected Validator<Token> createTokenValidator() {
			return JwtValidatorBuilder
					.getInstance(Environments.getCurrent().getXsuaaConfiguration())
					.withOAuth2TokenKeyService(tokenKeyService)
					.withOidcConfigurationService(oidcConfigurationService)
					.configureAnotherServiceInstance(getOtherXsuaaServiceConfiguration())
					.build();
	}

	private class XsuaaTokenExtractor implements TokenExtractor {
		@Override
		public Token from(String authorizationHeader) {
			if (Environments.getCurrent().getXsuaaConfiguration() != null) {
				return new XsuaaToken(authorizationHeader,
						Environments.getCurrent().getXsuaaConfiguration().getProperty(CFConstants.XSUAA.APP_ID));
			}
			throw new RuntimeException("XsuaaConfiguration not found. Are VCAP_SERVICES missing?");
		}
	}

	@Nullable
	private OAuth2ServiceConfiguration getOtherXsuaaServiceConfiguration() {
		if (Environments.getCurrent().getNumberOfXsuaaConfigurations() > 1) {
			return Environments.getCurrent().getXsuaaConfigurationForTokenExchange();
		}
		return null;
	}
}
