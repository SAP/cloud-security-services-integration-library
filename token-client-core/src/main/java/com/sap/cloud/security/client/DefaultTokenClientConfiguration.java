package com.sap.cloud.security.client;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default configuration class for the Token-Client. Loads default properties defined in this class.
 * This class is implemented as a singleton class. The default values can be overridden by accessing
 * the current instance of the class.
 *
 * <p>DefaultTokenClientConfiguration is configured with the following default values:
 *
 * <ul>
 *   <li>Is Retry Enabled - false
 *   <li>Max Retry Attempts - 3
 *   <li>Retry Delay Time - 1000 ms
 *   <li>Retry Status Codes - 408, 429, 500, 502, 503, 504
 * </ul>
 */
public class DefaultTokenClientConfiguration {

  private static volatile DefaultTokenClientConfiguration instance;
  private boolean isRetryEnabled = false;
  private int maxRetryAttempts = 3;
  private long retryDelayTime = 1000L;
  private Set<Integer> retryStatusCodes = Set.of(408, 429, 500, 502, 503, 504);
  private static final Logger LOGGER =
      LoggerFactory.getLogger(DefaultTokenClientConfiguration.class);

  /** Private constructor to prevent instantiation. */
  private DefaultTokenClientConfiguration() {}

  /**
   * Returns the singleton instance of DefaultTokenClientConfiguration.
   *
   * @return the singleton instance
   */
  public static DefaultTokenClientConfiguration getInstance() {
    if (instance == null) {
      synchronized (DefaultTokenClientConfiguration.class) {
        if (instance == null) {
          instance = new DefaultTokenClientConfiguration();
        }
      }
    }
    return instance;
  }

  /**
   * * Sets a new instance of DefaultTokenClientConfiguration. Set {@code null} to reset the
   * instance.
   *
   * @param newInstance the new instance to set
   */
  public static void setInstance(final DefaultTokenClientConfiguration newInstance) {
    synchronized (DefaultTokenClientConfiguration.class) {
      instance = newInstance;
    }
  }

  public boolean isRetryEnabled() {
    return isRetryEnabled;
  }

  public void setRetryEnabled(final boolean retryEnabled) {
    this.isRetryEnabled = retryEnabled;
  }

  public int getMaxRetryAttempts() {
    return maxRetryAttempts;
  }

  public void setMaxRetryAttempts(final int maxRetryAttempts) {
    this.maxRetryAttempts = maxRetryAttempts;
  }

  public long getRetryDelayTime() {
    return retryDelayTime;
  }

  public void setRetryDelayTime(final long retryDelayTime) {
    this.retryDelayTime = retryDelayTime;
  }

  public Set<Integer> getRetryStatusCodes() {
    return retryStatusCodes;
  }

  public void setRetryStatusCodes(final Set<Integer> retryStatusCodes) {
    this.retryStatusCodes = retryStatusCodes;
  }

  public void setRetryStatusCodes(final String retryStatusCodes) {
    try {
      setRetryStatusCodes(parseRetryStatusCodes(retryStatusCodes));
    } catch (final NumberFormatException e) {
      LOGGER.error("Failed to parse retry status codes: {}", retryStatusCodes, e);
      throw new IllegalStateException("Failed to parse retry status codes: " + retryStatusCodes, e);
    }
  }

  private Set<Integer> parseRetryStatusCodes(final String retryStatusCodes) {
    return Arrays.stream(Optional.ofNullable(retryStatusCodes).orElse("").split(","))
        .map(String::trim)
        .filter(s -> !s.isBlank())
        .map(Integer::parseInt)
        .collect(Collectors.toSet());
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
