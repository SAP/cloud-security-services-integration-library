/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import com.sap.cloud.security.config.Service;

@ConfigurationProperties("xsuaa")
public class XsuaaServiceConfigurationComp extends OAuth2ServiceConfigurationProperties {

	/**
	 * Creates a new instance to map configuration of a dedicated identity service.
	 *
	 */
	public XsuaaServiceConfigurationComp() {
		super(Service.XSUAA);
	}
}