/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.config.cf.CFConstants;

/**
 * Constants that simplifies access to service configuration properties in the
 * Kubernetes environment.
 */
public class K8sConstants {
	public static final String KUBERNETES_SERVICE_HOST = "KUBERNETES_SERVICE_HOST";

	private K8sConstants() {
	}

	/**
	 * Represents the service plans available in Kyma Service Catalog. The various
	 * plans are considered in {@code K8sEnvironment}
	 */
	public enum Plan {
		DEFAULT, BROKER, APPLICATION, SPACE, APIACCESS, SYSTEM;

		public static CFConstants.Plan from(String planAsString) {
			return CFConstants.Plan.valueOf(planAsString.toUpperCase());
		}

	}
}
