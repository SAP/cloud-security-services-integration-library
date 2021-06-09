/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa.junitjupiter;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import org.springframework.test.context.TestPropertySource;
import sample.spring.xsuaa.Application;

import static com.sap.cloud.security.test.SecurityTest.*;

@SpringBootTest(classes = Application.class)
@TestPropertySource(properties = {
		"xsuaa.clientid=" + DEFAULT_CLIENT_ID
})
@java.lang.SuppressWarnings("squid:S2699")
public class ApplicationTest {

	@Test
	public void whenSpringContextIsBootstrapped_thenNoExceptions() {
	}
}
