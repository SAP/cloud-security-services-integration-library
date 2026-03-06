package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration class for the Token Client.
 *
 * <p>This class is implemented as a configuration properties class, allowing for easy configuration
 * of the Token Client's retry behavior by setting the configured values to the
 * DefaultTokenClientConfiguration instance.
 *
 * <p>The properties are mapped from the `token.client.retry` prefix in the application's
 * configuration (e.g., `application.yml` or `application.properties`).
 */
@Configuration
@ConfigurationProperties("token.client.retry")
public class SpringTokenClientConfiguration {

  /**
   * Sets whether retry is enabled for the Token Client.
   *
   * @param retryEnabled a boolean indicating if retry is enabled
   */
  public void setRetryEnabled(final boolean retryEnabled) {
    DefaultTokenClientConfiguration.getInstance().setRetryEnabled(retryEnabled);
  }

  /**
   * Sets the maximum number of retry attempts for the Token Client.
   *
   * @param maxRetryAttempts an integer specifying the maximum retry attempts
   */
  public void setMaxRetryAttempts(final int maxRetryAttempts) {
    DefaultTokenClientConfiguration.getInstance().setMaxRetryAttempts(maxRetryAttempts);
  }

  /**
   * Sets the delay time between retry attempts for the Token Client.
   *
   * @param retryDelayTime a long value specifying the delay time in milliseconds
   */
  public void setRetryDelayTime(final long retryDelayTime) {
    DefaultTokenClientConfiguration.getInstance().setRetryDelayTime(retryDelayTime);
  }

  /**
   * Sets the HTTP status codes that should trigger a retry for the Token Client.
   *
   * @param retryStatusCodes a set of integers representing HTTP status codes
   */
  public void setRetryStatusCodes(final Set<Integer> retryStatusCodes) {
    DefaultTokenClientConfiguration.getInstance().setRetryStatusCodes(retryStatusCodes);
  }
}
