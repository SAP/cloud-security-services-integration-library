/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.ias.tokenflows.IasTokenFlows;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("sap.security.services.ias")
public class IasServiceConfiguration extends OAuth2ServiceConfigurationProperties {

	public IasServiceConfiguration() {
		super(Service.IAS);
	}

	/**
	 * Sets the base URI of the BTP tenant API
	 * ({@code sap.security.services.ias.btp-tenant-api}). When present, dynamic subscriber tenant
	 * host resolution is enabled for the auto-configured IAS token flows.
	 *
	 * @param btpTenantApi base URI of the BTP tenant API
	 */
	public void setBtpTenantApi(String btpTenantApi) {
		builder.withProperty(IasTokenFlows.BTP_TENANT_API_PROPERTY, btpTenantApi);
		buildRequired = true;
	}
}
