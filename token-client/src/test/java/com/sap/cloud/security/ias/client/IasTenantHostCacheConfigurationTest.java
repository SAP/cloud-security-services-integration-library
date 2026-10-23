/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.client;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IasTenantHostCacheConfigurationTest {

	@Test
	void defaultConfiguration_hasSensibleDefaults() {
		IasTenantHostCacheConfiguration config = IasTenantHostCacheConfiguration.defaultConfiguration();

		assertThat(config.enabled()).isTrue();
		assertThat(config.ttl()).isEqualTo(Duration.ofMinutes(15));
		assertThat(config.maxSize()).isEqualTo(1000L);
		assertThat(config.localInformationOnly()).isFalse();
	}

	@Test
	void builder_overridesDefaults() {
		IasTenantHostCacheConfiguration config = IasTenantHostCacheConfiguration.builder()
				.enabled(false)
				.ttl(Duration.ofMinutes(5))
				.maxSize(42)
				.localInformationOnly(true)
				.build();

		assertThat(config.enabled()).isFalse();
		assertThat(config.ttl()).isEqualTo(Duration.ofMinutes(5));
		assertThat(config.maxSize()).isEqualTo(42L);
		assertThat(config.localInformationOnly()).isTrue();
	}

	@Test
	void nullTtl_throws() {
		assertThatThrownBy(() -> new IasTenantHostCacheConfiguration(true, null, 100, false))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("ttl");
	}

	@Test
	void enabledWithNonPositiveMaxSize_throws() {
		assertThatThrownBy(() -> IasTenantHostCacheConfiguration.builder().maxSize(0).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("maxSize");
	}

	@Test
	void enabledWithNegativeTtl_throws() {
		assertThatThrownBy(() -> IasTenantHostCacheConfiguration.builder().ttl(Duration.ofSeconds(-1)).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("ttl");
	}

	@Test
	void disabled_skipsValidation() {
		IasTenantHostCacheConfiguration config = IasTenantHostCacheConfiguration.builder()
				.enabled(false)
				.maxSize(0)
				.build();

		assertThat(config.enabled()).isFalse();
	}
}