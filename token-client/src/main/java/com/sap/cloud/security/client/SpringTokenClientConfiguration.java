package com.sap.cloud.security.client;

import io.micrometer.common.util.StringUtils;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;

/**
 * Spring-based configuration class for the Token-Client. This class retrieves properties from the
 * Spring environment or application properties. It is recommended to use the static methods {@link
 * #getConfig()} and {@link #setConfig(SpringTokenClientConfiguration)} to access and modify the
 * configuration.
 *
 * <p>SpringTokenClientConfiguration is configured with the following default values: Is Retry
 * Enabled - false Max Retry Attempts - 3 Retry Delay Time - 1000 ms Retry Status Codes - 408, 429,
 * 500, 502, 503, 504
 */
public class SpringTokenClientConfiguration implements TokenClientConfiguration {

  private static SpringTokenClientConfiguration config = new SpringTokenClientConfiguration();

  @Value("${token.client.retry.enabled:false}")
  private boolean isRetryEnabled;

  @Value("${token.client.retry.maxAttempts:3}")
  private int maxRetryAttempts;

  @Value("${token.client.retry.delayTime:1000}")
  private long retryDelayTime;

  @Value("#{'${token.client.retry.statusCodes:408,429,500,502,503,504}'.split(',')}")
  private Set<Integer> retryStatusCodes;

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
  public Set<Integer> getRetryStatusCodes() {
    return retryStatusCodes;
  }

  @Override
  public void setRetryStatusCodes(final String retryStatusCodes) {
    this.retryStatusCodes = parseRetryStatusCodes(retryStatusCodes);
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

  private Set<Integer> parseRetryStatusCodes(final String retryStatusCodes) {
    return Arrays.stream(retryStatusCodes.split(","))
        .map(String::trim)
        .filter(StringUtils::isNotBlank)
        .map(
            s -> {
              try {
                return Integer.parseInt(s);
              } catch (final NumberFormatException e) {
                return null;
              }
            })
        .filter(Objects::nonNull)
        .collect(Collectors.toSet());
  }
}
