package com.sap.cloud.security.client;

import org.springframework.beans.factory.annotation.Value;

/**
 * Spring-based configuration class for the Token-Client.
 * This class retrieves properties from the Spring environment or application properties and allows users to override them dynamically.
 */

public class SpringTokenClientConfiguration implements TokenClientConfiguration {

    private static SpringTokenClientConfiguration config = new SpringTokenClientConfiguration();

    @Value("${token.client.retry.enabled:false}")
    private boolean isRetryEnabled;

    @Value("${token.client.retry.maxAttempts:3}")
    private int maxRetryAttempts;

    @Value("${token.client.retry.delayTime:1000}")
    private long retryDelayTime;

    @Value("${token.client.retry.statusCodes:408,429,500,502,503,504}")
    private String retryStatusCodes;

    public static SpringTokenClientConfiguration getConfig() {
        return config;
    }

    public static void setConfig(final SpringTokenClientConfiguration newConfig) {
        config = newConfig;
    }

    @Override
    public boolean isRetryEnabled() {
        return isRetryEnabled;
    }

    @Override
    public void setRetryEnabled(final boolean retryEnabled) {
        this.isRetryEnabled = retryEnabled;
    }

    @Override
    public int getMaxRetryAttempts() {
        return maxRetryAttempts;
    }

    @Override
    public void setMaxRetryAttempts(final int maxRetryAttempts) {
        this.maxRetryAttempts = maxRetryAttempts;
    }

    @Override
    public long getRetryDelayTime() {
        return retryDelayTime;
    }

    @Override
    public void setRetryDelayTime(final long retryDelayTime) {
        this.retryDelayTime = retryDelayTime;
    }

    @Override
    public String getRetryStatusCodes() {
        return retryStatusCodes;
    }

    @Override
    public void setRetryStatusCodes(final String retryStatusCodes) {
        this.retryStatusCodes = retryStatusCodes;
    }

    @Override
    public String toString() {
        return "SpringTokenClientConfig{" +
                "isRetryEnabled=" + isRetryEnabled +
                ", maxRetryAttempts=" + maxRetryAttempts +
                ", retryDelayTime=" + retryDelayTime +
                ", retryStatusCodes='" + retryStatusCodes + '\'' +
                '}';
    }
}
