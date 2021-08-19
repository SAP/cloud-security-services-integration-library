/*
  SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
  SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

/**
 * Constants that simplifies access to service configuration properties in the
 * Kubernetes environment.
 */
class K8sConstants {
	static final String DEFAULT_XSUAA_PATH = "/etc/secrets/sapcp/xsuaa";
	static final String DEFAULT_IAS_PATH = "/etc/secrets/sapcp/ias";
	static final String DEFAULT_SERVICE_MANAGER_PATH = "/etc/secrets/sapcp/service-manager";

	private K8sConstants() {
	}
}
