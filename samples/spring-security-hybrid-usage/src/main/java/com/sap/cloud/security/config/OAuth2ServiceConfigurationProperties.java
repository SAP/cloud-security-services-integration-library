package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFConstants;

import java.net.URI;
import java.util.Map;

public class OAuth2ServiceConfigurationProperties implements OAuth2ServiceConfiguration {
    OAuth2ServiceConfigurationBuilder builder;
    OAuth2ServiceConfiguration configuration;

    public OAuth2ServiceConfigurationProperties(Service service) {
        builder = OAuth2ServiceConfigurationBuilder.forService(service);
    }

    @Override
    public String getClientId() {
        return getConfiguration().getClientId();
    }

    public void setClientId(String clientId) {
        builder.withClientId(clientId);
    }

    @Override
    public String getClientSecret() {
        return getConfiguration().getClientSecret();
    }

    public void setClientSecret(String clientSecret) {
        builder.withClientSecret(clientSecret);
    }

    @Override
    public URI getUrl() {
        return getConfiguration().getUrl();
    }

    public void setUrl(String url) {
        builder.withUrl(url);
    }

    public void setUaaDomain(String uaaDomain) {
        builder.withProperty(CFConstants.XSUAA.UAA_DOMAIN, uaaDomain);
    }

    public void setXsAppName(String xsAppName) {
        builder.withProperty(CFConstants.XSUAA.APP_ID, xsAppName);
    }

    public void setVerificationKey(String verificationKey) {
        builder.withProperty(CFConstants.XSUAA.VERIFICATION_KEY, verificationKey);
    }

    @Override
    public String getProperty(String name) {
        return getConfiguration().getProperty(name);
    }

    @Override
    public Map<String, String> getProperties() {
        return getConfiguration().getProperties();
    }

    @Override
    public boolean hasProperty(String name) {
        return getConfiguration().hasProperty(name);
    }

    @Override
    public Service getService() {
        return getConfiguration().getService();
    }

    @Override
    public boolean isLegacyMode() {
        return getConfiguration().isLegacyMode();
    }

    protected OAuth2ServiceConfiguration getConfiguration() {
        if (configuration == null) {
            configuration = builder.build();
        }
        return configuration;
    }
}
