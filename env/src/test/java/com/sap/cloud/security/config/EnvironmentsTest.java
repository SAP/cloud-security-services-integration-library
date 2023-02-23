/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class EnvironmentsTest {

	@Test
	void getCurrent_returnsOnlySingleInstance() {
		Environment firstEnvironment = Environments.getCurrent();
		Environment secondEnvironment = Environments.getCurrent();

		Assertions.assertThat(firstEnvironment).isSameAs(secondEnvironment);
	}

}
