package com.sap.cloud.security.client;

import java.util.Set;

/**
 * Default configuration class for the Token-Client. Loads default properties defined in this class.
 * It is recommended to use the static methods {@link #getConfig()} and {@link
 * #setConfig(DefaultTokenClientConfiguration)} to access and modify the configuration.
 *
 * <p>DefaultTokenClientConfiguration is configured with the following default values: Is Retry
 * Enabled - false Max Retry Attempts - 3 Retry Delay Time - 1000 ms Retry Status Codes - 408, 429,
 * 500, 502, 503, 504
 */
public class DefaultTokenClientConfiguration implements TokenClientConfiguration {

  private static DefaultTokenClientConfiguration config = new DefaultTokenClientConfiguration();
  private boolean isRetryEnabled;
  private int maxRetryAttempts;
  private long retryDelayTime;
  private Set<Integer> retryStatusCodes;

  /** Constructs a new DefaultTokenClientConfiguration instance with default values. */
  public DefaultTokenClientConfiguration() {
    loadDefaults();
  }

  public static DefaultTokenClientConfiguration getConfig() {
    return config;
  }

  public static void setConfig(final DefaultTokenClientConfiguration newConfig) {
    config = newConfig;
  }

  private void loadDefaults() {
    this.isRetryEnabled = false;
    this.maxRetryAttempts = 3;
    this.retryDelayTime = 1000L;
    this.retryStatusCodes = Set.of(408, 429, 500, 502, 503, 504);
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
  public Set<Integer> getRetryStatusCodes() {
    return retryStatusCodes;
  }

  @Override
  public void setRetryStatusCodes(final Set<Integer> retryStatusCodes) {
    this.retryStatusCodes = retryStatusCodes;
  }

  @Override
  public String toString() {
    return "DefaultTokenClientConfig{"
        + "isRetryEnabled="
        + isRetryEnabled
        + ", maxRetryAttempts="
        + maxRetryAttempts
        + ", retryDelayTime="
        + retryDelayTime
        + ", retryStatusCodes='"
        + retryStatusCodes
        + '\''
        + '}';
  }
}
