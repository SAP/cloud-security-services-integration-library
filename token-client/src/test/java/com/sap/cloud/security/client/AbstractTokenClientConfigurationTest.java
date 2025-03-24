package com.sap.cloud.security.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

public abstract class AbstractTokenClientConfigurationTest {

  protected abstract TokenClientConfiguration createConfig();

  @Test
  public void setRetryStatusCodes_withString_updatesValue() {
    final TokenClientConfiguration config = createConfig();
    config.setRetryStatusCodes("400,401");
    assertThat(config.getRetryStatusCodes()).containsExactlyInAnyOrder(400, 401);
  }

  @Test
  public void setRetryStatusCodes_withEmptyString() {
    final TokenClientConfiguration config = createConfig();
    config.setRetryStatusCodes("");
    assertThat(config.getRetryStatusCodes()).isEmpty();
  }

  @Test
  public void setRetryStatusCodes_withInvalidString() {
    final TokenClientConfiguration config = createConfig();
    assertThatThrownBy(() -> config.setRetryStatusCodes("abc,123"))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  public void setRetryStatusCodes_withNullString() {
    final TokenClientConfiguration config = createConfig();
    config.setRetryStatusCodes((String) null);
    assertThat(config.getRetryStatusCodes()).isEmpty();
  }

  @Test
  public void setRetryStatusCodes_withSpacesOnly() {
    final TokenClientConfiguration config = createConfig();
    config.setRetryStatusCodes("   ");
    assertThat(config.getRetryStatusCodes()).isEmpty();
  }

  @Test
  public void setRetryStatusCodes_withMixedValidAndInvalidCodes() {
    final TokenClientConfiguration config = createConfig();
    assertThatThrownBy(() -> config.setRetryStatusCodes("200,abc,404,xyz"))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  public void setRetryStatusCodes_withDuplicateCodes() {
    final TokenClientConfiguration config = createConfig();
    config.setRetryStatusCodes("500,500,502,502");
    assertThat(config.getRetryStatusCodes()).containsExactlyInAnyOrder(500, 502);
  }

  @Test
  public void setRetryStatusCodes_withLeadingAndTrailingCommas() {
    final TokenClientConfiguration config = createConfig();
    config.setRetryStatusCodes(",400,401,");
    assertThat(config.getRetryStatusCodes()).containsExactlyInAnyOrder(400, 401);
  }
}
