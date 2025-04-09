package com.sap.cloud.security.client;

import java.util.Set;
import org.springframework.beans.factory.annotation.Value;

/**
 * Spring configuration class for the Token-Client. Loads properties from Spring's environment. This
 * class is implemented as a singleton class. The default values can be overridden by accessing the
 * current instance of the class.
 *
 * <p>SpringTokenClientConfiguration is configured with the following default values:
 *
 * <ul>
 *   <li>Is Retry Enabled - false
 *   <li>Max Retry Attempts - 3
 *   <li>Retry Delay Time - 1000 ms
 *   <li>Retry Status Codes - 408, 429, 500, 502, 503, 504
 * </ul>
 */
public class SpringTokenClientConfiguration implements TokenClientConfiguration {

  private static volatile SpringTokenClientConfiguration instance;

  @Value("${token.client.retry.enabled:false}")
  private boolean isRetryEnabled;

  @Value("${token.client.retry.maxAttempts:3}")
  private int maxRetryAttempts;

  @Value("${token.client.retry.delayTime:1000}")
  private long retryDelayTime;

  @Value("${token.client.retry.statusCodes:408,429,500,502,503,504}")
  private Set<Integer> retryStatusCodes;

  /** Private constructor to prevent instantiation. */
  private SpringTokenClientConfiguration() {}

  /**
   * Returns the singleton instance of SpringTokenClientConfiguration.
   *
   * @return the singleton instance
   */
  public static SpringTokenClientConfiguration getInstance() {
    if (instance == null) {
      synchronized (SpringTokenClientConfiguration.class) {
        if (instance == null) {
          instance = new SpringTokenClientConfiguration();
        }
      }
    }
    return instance;
  }

  /**
   * Sets a new instance of SpringTokenClientConfiguration. Set {@code null} to reset the instance.
   *
   * @param newInstance the new instance to set
   */
  public static void setInstance(final SpringTokenClientConfiguration newInstance) {
    synchronized (SpringTokenClientConfiguration.class) {
      instance = newInstance;
    }
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
    return "SpringTokenClientConfig{"
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
