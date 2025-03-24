package com.sap.cloud.security.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DefaultTokenClientConfigurationTest extends AbstractTokenClientConfigurationTest {

  private DefaultTokenClientConfiguration config;

  @BeforeEach
  public void setUp() {
    config = new DefaultTokenClientConfiguration();
  }

  @Override
  protected TokenClientConfiguration createConfig() {
    return config;
  }

  @Test
  public void testStaticGetterAndSetter() {
    DefaultTokenClientConfiguration.setConfig(config);
    assertThat(DefaultTokenClientConfiguration.getConfig()).isEqualTo(config);
  }

  @Test
  public void defaultValues_areSetCorrectly() {
    assertThat(config.isRetryEnabled()).isFalse();
    assertThat(config.getMaxRetryAttempts()).isEqualTo(3);
    assertThat(config.getRetryDelayTime()).isEqualTo(1000L);
    assertThat(config.getRetryStatusCodes())
        .containsExactlyInAnyOrder(408, 429, 500, 502, 503, 504);
  }

  @Test
  public void setRetryEnabled_updatesValue() {
    config.setRetryEnabled(true);
    assertThat(config.isRetryEnabled()).isTrue();
  }

  @Test
  public void setMaxRetryAttempts_updatesValue() {
    config.setMaxRetryAttempts(5);
    assertThat(config.getMaxRetryAttempts()).isEqualTo(5);
  }

  @Test
  public void setRetryDelayTime_updatesValue() {
    config.setRetryDelayTime(2000L);
    assertThat(config.getRetryDelayTime()).isEqualTo(2000L);
  }

  @Test
  public void setRetryStatusCodes_withIntegerSet_updatesValue() {
    config.setRetryStatusCodes(Set.of(400, 401));
    assertThat(config.getRetryStatusCodes()).containsExactlyInAnyOrder(400, 401);
  }

  @Test
  public void testToString() {
    final String result = config.toString();
    assertThat(result).startsWith("DefaultTokenClientConfig{");
    assertThat(result).contains("isRetryEnabled=false");
    assertThat(result).contains("maxRetryAttempts=3");
    assertThat(result).contains("retryDelayTime=1000");
    assertThat(result).contains("retryStatusCodes='[");
    assertThat(result)
        .contains("408")
        .contains("429")
        .contains("500")
        .contains("502")
        .contains("503")
        .contains("504");
  }
}
