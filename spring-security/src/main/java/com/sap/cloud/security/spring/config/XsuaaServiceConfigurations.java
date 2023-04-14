/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p> 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties("sap.security.services")
public class XsuaaServiceConfigurations {
	@NestedConfigurationProperty
	private List<XsuaaServiceConfiguration> xsuaa = new ArrayList<>();

	public List<XsuaaServiceConfiguration> getConfigurations() {
		return this.xsuaa;
	}

	public void setXsuaa(List<XsuaaServiceConfiguration> xsuaa) {
		this.xsuaa = xsuaa;
	}

}
