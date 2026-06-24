/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.ias.client.IasTenantHostCacheConfiguration;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for the IAS tenant host resolver cache.
 * <p>
 * Bind from {@code application.yml} / {@code application.properties} under the prefix
 * {@code sap.spring.security.ias.tenant-host-cache}:
 *
 * <pre>{@code
 * sap:
 *   spring:
 *     security:
 *       ias:
 *         tenant-host-cache:
 *           enabled: true        # default: true
 *           ttl: 1h              # default: 1 hour (any java.time.Duration string)
 *           max-size: 1000       # default: 1000
 * }</pre>
 *
 * Exposes a {@link IasTenantHostCacheConfiguration} bean that an
 * {@code IasTenantHostResolver} or auto-configuration can consume.
 */
@Configuration
@ConfigurationProperties("sap.spring.security.ias.tenant-host-cache")
public class IasTenantHostCacheProperties {

	private boolean enabled = true;
	private Duration ttl = Duration.ofHours(1);
	private long maxSize = 1000L;

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(final boolean enabled) {
		this.enabled = enabled;
	}

	public Duration getTtl() {
		return ttl;
	}

	public void setTtl(final Duration ttl) {
		this.ttl = ttl;
	}

	public long getMaxSize() {
		return maxSize;
	}

	public void setMaxSize(final long maxSize) {
		this.maxSize = maxSize;
	}

	/**
	 * Exposes the bound properties as an immutable {@link IasTenantHostCacheConfiguration}.
	 */
	@Bean
	public IasTenantHostCacheConfiguration iasTenantHostCacheConfiguration() {
		return IasTenantHostCacheConfiguration.builder()
				.enabled(enabled)
				.ttl(ttl)
				.maxSize(maxSize)
				.build();
	}
}