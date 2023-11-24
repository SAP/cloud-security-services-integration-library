/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa.junitjupiter;

import com.sap.cloud.security.test.extension.XsuaaExtension;

public class XsuaaExtensionFixedPort extends XsuaaExtension {

	public XsuaaExtensionFixedPort() {
		super();
		this.setPort(2224);
	}
}
