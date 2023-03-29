/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.security.junitjupiter;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@java.lang.SuppressWarnings("squid:S2699")
@ActiveProfiles("multixsuaa") // properties are provided with /resources/application-multixsuaa.yml
class ApplicationTest {
    @Autowired
    XsuaaTokenFlows tokenflows;

    @Test
    void whenSpringContextIsBootstrapped_thenNoExceptions() {
        assertNotNull(tokenflows.clientCredentialsTokenFlow());
    }
}
