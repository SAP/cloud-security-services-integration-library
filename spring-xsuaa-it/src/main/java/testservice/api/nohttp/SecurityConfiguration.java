/*
 * Copyright 2018-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
