package com.sap.cloud.security.client;

/**
 * Default configuration class for the Token-Client.
 * Loads default properties defined in this class. Allows users to override them dynamically using setters.
 */

public class DefaultTokenClientConfiguration implements TokenClientConfiguration {

    private static DefaultTokenClientConfiguration instance;
    private static DefaultTokenClientConfiguration config = new DefaultTokenClientConfiguration();
    private boolean isRetryEnabled;
    private int maxRetryAttempts;
    private long retryDelayTime;
    private String retryStatusCodes;

    /**
     * Constructs a new DefaultTokenClientConfiguration instance with default values.
     */
    public DefaultTokenClientConfiguration() {
        loadDefaults();
    }

    public static DefaultTokenClientConfiguration getConfig() {
        return config;
    }

    public static void setConfig(final DefaultTokenClientConfiguration newConfig) {
        config = newConfig;
    }

    /**
     * Loads default values for retry configuration.
     */
    private void loadDefaults() {
        this.isRetryEnabled = false;
        this.maxRetryAttempts = 3;
        this.retryDelayTime = 1000L;
        this.retryStatusCodes = "408,429,500,502,503,504";
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
        return "DefaultTokenClientConfig{" +
                "isRetryEnabled=" + isRetryEnabled +
                ", maxRetryAttempts=" + maxRetryAttempts +
                ", retryDelayTime=" + retryDelayTime +
                ", retryStatusCodes='" + retryStatusCodes + '\'' +
                '}';
    }
}
