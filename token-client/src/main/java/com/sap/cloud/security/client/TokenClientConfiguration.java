package com.sap.cloud.security.client;

import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configuration interface for the Token Client. Defines methods for configuring retry behavior and
 * other settings related to token retrieval.
 */
public interface TokenClientConfiguration {

  Logger logger = LoggerFactory.getLogger(TokenClientConfiguration.class);

  /**
   * Checks if the retry mechanism is enabled.
   *
   * @return true if retry is enabled, false otherwise.
   */
  boolean isRetryEnabled();

  /**
   * Sets whether the retry mechanism should be enabled.
   *
   * @param retryEnabled true to enable retry, false to disable.
   */
  void setRetryEnabled(boolean retryEnabled);

  /**
   * Gets the maximum number of retry attempts.
   *
   * @return The maximum number of retries.
   */
  int getMaxRetryAttempts();

  /**
   * Sets the maximum number of retry attempts.
   *
   * @param maxRetryAttempts The number of retries to allow.
   */
  void setMaxRetryAttempts(int maxRetryAttempts);

  /**
   * Gets the retry delay time in milliseconds.
   *
   * @return The retry delay time.
   */
  long getRetryDelayTime();

  /**
   * Sets the retry delay time in milliseconds.
   *
   * @param retryDelayTime The delay between retries.
   */
  void setRetryDelayTime(long retryDelayTime);

  /**
   * Gets the retry status codes.
   *
   * @return A comma-separated string of HTTP status codes.
   */
  Set<Integer> getRetryStatusCodes();

  /**
   * Sets the retry status codes.
   *
   * @param retryStatusCodes A Set of Integer values representing http status codes.
   */
  void setRetryStatusCodes(Set<Integer> retryStatusCodes);

  /**
   * Sets the retry status codes.
   *
   * @param retryStatusCodes A comma-separated string of HTTP status codes to retry on.
   */
  void setRetryStatusCodes(String retryStatusCodes);
}
