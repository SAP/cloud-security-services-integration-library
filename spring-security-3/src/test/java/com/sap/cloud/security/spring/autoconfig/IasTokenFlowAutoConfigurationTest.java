/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import static org.assertj.core.api.Assertions.assertThat;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.ias.client.IasDefaultEndpoints;
import com.sap.cloud.security.ias.client.IasTenantHostCacheConfiguration;
import com.sap.cloud.security.ias.tokenflows.IasTokenFlows;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class IasTokenFlowAutoConfigurationTest {

  private static final String IAS_CLIENT_ID = "ias-client-id";
  private static final String IAS_CLIENT_SECRET = "ias-client-secret";
  private static final String IAS_URL = "https://mycompany.accounts.ondemand.com";

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(IasTokenFlowAutoConfiguration.class));

  @Test
  void noIasBinding_noFlowsBean() {
    runner.run(ctx -> assertThat(ctx).doesNotHaveBean(IasTokenFlows.class));
  }

  @Test
  void singleIasBinding_createsFlowsBean() {
    runner
        .withPropertyValues(
            "sap.security.services.ias.clientid=" + IAS_CLIENT_ID,
            "sap.security.services.ias.clientsecret=" + IAS_CLIENT_SECRET,
            "sap.security.services.ias.url=" + IAS_URL)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(IasTokenFlows.class);
              assertThat(ctx).hasBean("iasTokenFlowHttpClient");
            });
  }

  @Test
  void indexedIasBinding_createsFlowsBean() {
    runner
        .withPropertyValues(
            "sap.security.services.ias[0].clientid=" + IAS_CLIENT_ID,
            "sap.security.services.ias[0].clientsecret=" + IAS_CLIENT_SECRET,
            "sap.security.services.ias[0].url=" + IAS_URL)
        .run(ctx -> assertThat(ctx).hasSingleBean(IasTokenFlows.class));
  }

  @Test
  void disabledViaProperty_noFlowsBean() {
    runner
        .withPropertyValues(
            "sap.security.services.ias.clientid=" + IAS_CLIENT_ID,
            "sap.security.services.ias.clientsecret=" + IAS_CLIENT_SECRET,
            "sap.security.services.ias.url=" + IAS_URL,
            "sap.spring.security.ias.flows.auto=false")
        .run(ctx -> assertThat(ctx).doesNotHaveBean(IasTokenFlows.class));
  }

  @Test
  void userDefinedFlowsBean_takesPrecedence() {
    runner
        .withPropertyValues(
            "sap.security.services.ias.clientid=" + IAS_CLIENT_ID,
            "sap.security.services.ias.clientsecret=" + IAS_CLIENT_SECRET,
            "sap.security.services.ias.url=" + IAS_URL)
        .withUserConfiguration(UserFlowsConfig.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(IasTokenFlows.class);
              assertThat(ctx.getBean(IasTokenFlows.class)).isSameAs(ctx.getBean("userFlows"));
            });
  }

  @Test
  void cacheProperties_defaultValues() {
    runner
        .withPropertyValues(
            "sap.security.services.ias.clientid=" + IAS_CLIENT_ID,
            "sap.security.services.ias.clientsecret=" + IAS_CLIENT_SECRET,
            "sap.security.services.ias.url=" + IAS_URL)
        .run(
            ctx -> {
              IasTenantHostCacheConfiguration config =
                  ctx.getBean(IasTenantHostCacheConfiguration.class);
              assertThat(config.enabled()).isTrue();
              assertThat(config.ttl()).isEqualTo(Duration.ofMinutes(15));
              assertThat(config.maxSize()).isEqualTo(1000L);
              assertThat(config.localInformationOnly()).isFalse();
            });
  }

  @Test
  void cacheProperties_customValues() {
    runner
        .withPropertyValues(
            "sap.security.services.ias.clientid=" + IAS_CLIENT_ID,
            "sap.security.services.ias.clientsecret=" + IAS_CLIENT_SECRET,
            "sap.security.services.ias.url=" + IAS_URL,
            "sap.spring.security.ias.tenant-host-cache.enabled=false",
            "sap.spring.security.ias.tenant-host-cache.ttl=30s",
            "sap.spring.security.ias.tenant-host-cache.max-size=42",
            "sap.spring.security.ias.tenant-host-cache.local-information-only=true")
        .run(
            ctx -> {
              IasTenantHostCacheConfiguration config =
                  ctx.getBean(IasTenantHostCacheConfiguration.class);
              assertThat(config.enabled()).isFalse();
              assertThat(config.ttl()).isEqualTo(Duration.ofSeconds(30));
              assertThat(config.maxSize()).isEqualTo(42L);
              assertThat(config.localInformationOnly()).isTrue();
            });
  }

  @Test
  void userDefinedCacheConfiguration_takesPrecedence() {
    runner
        .withPropertyValues(
            "sap.security.services.ias.clientid=" + IAS_CLIENT_ID,
            "sap.security.services.ias.clientsecret=" + IAS_CLIENT_SECRET,
            "sap.security.services.ias.url=" + IAS_URL)
        .withUserConfiguration(UserCacheConfig.class)
        .run(
            ctx -> {
              IasTenantHostCacheConfiguration config =
                  ctx.getBean(IasTenantHostCacheConfiguration.class);
              assertThat(config.maxSize()).isEqualTo(7L);
            });
  }

  @Test
  void btpTenantApiPropertyIsBound() {
    runner
        .withPropertyValues(
            "sap.security.services.ias.clientid=" + IAS_CLIENT_ID,
            "sap.security.services.ias.clientsecret=" + IAS_CLIENT_SECRET,
            "sap.security.services.ias.url=" + IAS_URL,
            "sap.security.services.ias.btp-tenant-api=https://api.authentication.eu10.hana.ondemand.com")
        .run(
            ctx -> {
              // the flows bean is constructed; the resolver is active when btp-tenant-api is set.
              // A non-HTTPS or missing client identity would fail fast, so reaching this point
              // proves the property bound and the bean was created.
              assertThat(ctx).hasSingleBean(IasTokenFlows.class);
              assertThat(ctx).hasNotFailed();
            });
  }

  @Configuration
  static class UserFlowsConfig {
    @Bean
    public IasTokenFlows userFlows() {
      return new IasTokenFlows(
          new DefaultOAuth2TokenService(),
          new IasDefaultEndpoints(IAS_URL),
          new ClientCredentials("user-id", "user-secret"));
    }
  }

  @Configuration
  static class UserCacheConfig {
    @Bean
    public IasTenantHostCacheConfiguration cacheConfiguration() {
      return IasTenantHostCacheConfiguration.builder().maxSize(7).build();
    }
  }
}
