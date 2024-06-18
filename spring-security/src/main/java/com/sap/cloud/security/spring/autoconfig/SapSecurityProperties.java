/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

public class SapSecurityProperties {

	static final String SAP_SECURITY_SERVICES_IDENTITY_DOMAINS = "sap.security.services.identity.domains";
	static final String SAP_SECURITY_SERVICES_XSUAA_UAADOMAIN = "sap.security.services.xsuaa.uaadomain";
	static final String SAP_SECURITY_SERVICES_XSUAA_0_UAADOMAIN = "sap.security.services.xsuaa[0].uaadomain";
	static final String SAP_SPRING_SECURITY_IDENTITY_PROOFTOKEN = "sap.spring.security.identity.prooftoken";
	static final String SAP_SPRING_SECURITY_HYBRID = "sap.spring.security.hybrid.auto";

	private SapSecurityProperties() {
	}
}
