/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.extension;

import com.sap.cloud.security.test.api.SecurityTestContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(XsuaaExtension.class)
public class XsuaaExtensionTest {

	@Test
	void resolveSecurityTestConfigurationParameter(SecurityTestContext context) {
		assertNotNull(context);
		assertThat(context.getWireMockServer().isRunning()).isTrue();
	}
}