/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

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
 *           enabled: true               # default: true
 *           ttl: 15m                    # default: 15 minutes (any java.time.Duration string)
 *           max-size: 1000              # default: 1000
 *           local-information-only: false  # default: false
 * }</pre>
 *
 * <p>The {@code IasTokenFlowAutoConfiguration} exposes these values as an
 * {@link com.sap.cloud.security.ias.client.IasTenantHostCacheConfiguration} bean
 * ({@code @ConditionalOnMissingBean}); provide your own bean to override.
 */
@ConfigurationProperties("sap.spring.security.ias.tenant-host-cache")
public class IasTenantHostCacheProperties {

	private boolean enabled = true;
	private Duration ttl = Duration.ofMinutes(15);
	private long maxSize = 1000L;
	private boolean localInformationOnly = false;

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

	public boolean isLocalInformationOnly() {
		return localInformationOnly;
	}

	public void setLocalInformationOnly(final boolean localInformationOnly) {
		this.localInformationOnly = localInformationOnly;
	}
}
