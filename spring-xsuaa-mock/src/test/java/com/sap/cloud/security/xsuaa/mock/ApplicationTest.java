/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.mock;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import com.sap.cloud.security.xsuaa.mock.autoconfiguration.XsuaaMockAutoConfiguration;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = { XsuaaMockAutoConfiguration.class, MockXsuaaServiceConfiguration.class })
@java.lang.SuppressWarnings("squid:S2699")
public class ApplicationTest {

	@Test
	public void contextLoads() {
	}

}
