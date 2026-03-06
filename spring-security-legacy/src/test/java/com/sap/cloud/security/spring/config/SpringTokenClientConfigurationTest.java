package com.sap.cloud.security.spring.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

public class SpringTokenClientConfigurationTest {

  private SpringTokenClientConfiguration cut;

  @BeforeEach
  void setUp() {
    cut = new SpringTokenClientConfiguration();
  }

  @Test
  void retryEnabledIsSetCorrectly() {
    cut.setRetryEnabled(true);
    Assertions.assertTrue(DefaultTokenClientConfiguration.getInstance().isRetryEnabled());
  }

  @Test
  void maxRetryAttemptsIsSetCorrectly() {
    cut.setMaxRetryAttempts(5);
    assertEquals(5, DefaultTokenClientConfiguration.getInstance().getMaxRetryAttempts());
  }

  @Test
  void retryDelayTimeIsSetCorrectly() {
    cut.setRetryDelayTime(2000L);
    assertEquals(2000L, DefaultTokenClientConfiguration.getInstance().getRetryDelayTime());
  }

  @Test
  void retryStatusCodesAreSetCorrectly() {
    cut.setRetryStatusCodes(Set.of(500, 502, 503));
    assertEquals(
        Set.of(500, 502, 503), DefaultTokenClientConfiguration.getInstance().getRetryStatusCodes());
  }

  @Test
  void propertiesAreBoundCorrectly() {
    final Map<String, Object> properties =
        Map.of(
            "token.client.retry.retryEnabled",
            true,
            "token.client.retry.maxRetryAttempts",
            3,
            "token.client.retry.retryDelayTime",
            1000L,
            "token.client.retry.retryStatusCodes",
            "500,502,503");

    final Binder binder = new Binder(new MapConfigurationPropertySource(properties));
    binder
        .bind("token.client.retry", SpringTokenClientConfiguration.class)
        .ifBound(
            config -> {
              config.setRetryEnabled(true);
              config.setMaxRetryAttempts(3);
              config.setRetryDelayTime(1000L);
              config.setRetryStatusCodes(Set.of(500, 502, 503));
            });

    assertTrue(DefaultTokenClientConfiguration.getInstance().isRetryEnabled());
    assertEquals(3, DefaultTokenClientConfiguration.getInstance().getMaxRetryAttempts());
    assertEquals(1000L, DefaultTokenClientConfiguration.getInstance().getRetryDelayTime());
    assertEquals(
        Set.of(500, 502, 503), DefaultTokenClientConfiguration.getInstance().getRetryStatusCodes());
  }
}