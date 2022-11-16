/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.extension;

import com.sap.cloud.security.config.Service;

public class XsuaaExtension extends SecurityTestExtension {

	public XsuaaExtension() {
		super(Service.XSUAA);
	}
}
