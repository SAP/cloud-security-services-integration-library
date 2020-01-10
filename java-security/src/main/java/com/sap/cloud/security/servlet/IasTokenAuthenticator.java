package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.IasToken;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;

public class IasTokenAuthenticator extends AbstractTokenAuthenticator {

	public IasTokenAuthenticator() {
		tokenKeyService = OAuth2TokenKeyServiceWithCache.getInstance();
		oidcConfigurationService = OidcConfigurationServiceWithCache.getInstance();
	}

	@Override
	public TokenExtractor getTokenExtractor() {
		return IasToken::new;
	}

	@Override
	protected OAuth2ServiceConfiguration getServiceConfiguration() {
		return serviceConfiguration != null ? serviceConfiguration : Environments.getCurrent().getIasConfiguration();
	}
}
