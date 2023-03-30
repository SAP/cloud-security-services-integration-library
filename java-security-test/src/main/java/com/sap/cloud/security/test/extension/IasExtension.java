/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.extension;

import com.sap.cloud.security.config.Service;

public class IasExtension extends SecurityTestExtension {

	public IasExtension() {
		super(Service.IAS);
	}
}
