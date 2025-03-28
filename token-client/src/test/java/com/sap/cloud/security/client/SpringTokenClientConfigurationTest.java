package com.sap.cloud.security.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SpringTokenClientConfigurationTest extends AbstractTokenClientConfigurationTest {

  private SpringTokenClientConfiguration config;

  @BeforeEach
  public void setUp() {
    SpringTokenClientConfiguration.setInstance(null);
    config = SpringTokenClientConfiguration.getInstance();
    config.setRetryEnabled(false);
    config.setMaxRetryAttempts(3);
    config.setRetryDelayTime(1000L);
    config.setRetryStatusCodes(Set.of(408, 429, 500, 502, 503, 504));
  }

  @Override
  protected TokenClientConfiguration createConfig() {
    return config;
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
    config.setRetryStatusCodes(Set.of(300, 301));
    assertThat(config.getRetryStatusCodes()).containsExactlyInAnyOrder(300, 301);
  }

  @Test
  public void testToString() {
    final String result = config.toString();
    assertThat(result).startsWith("SpringTokenClientConfig{");
    assertThat(result).contains("isRetryEnabled=false");
    assertThat(result).contains("maxRetryAttempts=3");
    assertThat(result).contains("retryDelayTime=1000");
    assertThat(result).contains("retryStatusCodes='[");
    assertThat(result).contains("408");
    assertThat(result).contains("429");
    assertThat(result).contains("500");
    assertThat(result).contains("502");
    assertThat(result).contains("503");
    assertThat(result).contains("504");
  }

  @Test
  public void setInstance_resetsSingleton() {
    SpringTokenClientConfiguration.setInstance(null);
    final SpringTokenClientConfiguration newConfig = SpringTokenClientConfiguration.getInstance();
    assertThat(newConfig).isNotSameAs(config);
  }

  @Test
  public void testSingletonInstanceIsSameAcrossThreads()
      throws InterruptedException, ExecutionException, TimeoutException {
    final Callable<SpringTokenClientConfiguration> task =
        SpringTokenClientConfiguration::getInstance;
    final ExecutorService executorService = Executors.newFixedThreadPool(2);

    final Future<SpringTokenClientConfiguration> future1 = executorService.submit(task);
    final Future<SpringTokenClientConfiguration> future2 = executorService.submit(task);

    final SpringTokenClientConfiguration instance1 = future1.get(1, TimeUnit.SECONDS);
    final SpringTokenClientConfiguration instance2 = future2.get(1, TimeUnit.SECONDS);

    assertThat(instance1).isSameAs(instance2);

    executorService.shutdown();
  }

  @Test
  public void testSingletonPropertiesAreConsistentAcrossThreads()
      throws InterruptedException, ExecutionException, TimeoutException {
    final SpringTokenClientConfiguration instance = SpringTokenClientConfiguration.getInstance();
    instance.setRetryEnabled(true);

    final Callable<Boolean> task =
        () -> SpringTokenClientConfiguration.getInstance().isRetryEnabled();
    final ExecutorService executorService = Executors.newFixedThreadPool(2);

    final Future<Boolean> future1 = executorService.submit(task);
    final Future<Boolean> future2 = executorService.submit(task);

    final Boolean value1 = future1.get(1, TimeUnit.SECONDS);
    final Boolean value2 = future2.get(1, TimeUnit.SECONDS);

    assertThat(value1).isTrue();
    assertThat(value2).isTrue();

    executorService.shutdown();
  }
}
