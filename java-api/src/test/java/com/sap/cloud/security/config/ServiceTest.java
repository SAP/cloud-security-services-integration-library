/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import org.junit.Test;

import static org.assertj.core.api.Assertions.*;

public class ServiceTest {

	@Test
	public void getCFNameOfIas_shouldReturnCorrectName() {
		assertThat(Service.IAS.getCFName()).isEqualTo("identity");
	}

	@Test
	public void getCFNameOfXsuaa_shouldReturnCorrectName() {
		assertThat(Service.XSUAA.getCFName()).isEqualTo("xsuaa");
	}

}