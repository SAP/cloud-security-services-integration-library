/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package testservice.api.nohttp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.mock.MockXsuaaServiceConfiguration;

@Configuration
// @EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Profile({ "test.api.nohttp" })
public class SecurityConfiguration {

	@Bean
	XsuaaServiceConfiguration getXsuaaServiceConfiguration() {
		return new MockXsuaaServiceConfiguration();
	}
}
