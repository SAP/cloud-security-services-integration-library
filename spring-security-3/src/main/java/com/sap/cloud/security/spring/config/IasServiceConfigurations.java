/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties("sap.security.services")
public class IasServiceConfigurations {
	@NestedConfigurationProperty
	private List<IasServiceConfiguration> ias = new ArrayList<>();

	public List<IasServiceConfiguration> getConfigurations() {
		return this.ias;
	}

	public void setIas(List<IasServiceConfiguration> ias) {
		this.ias = ias;
	}
}
