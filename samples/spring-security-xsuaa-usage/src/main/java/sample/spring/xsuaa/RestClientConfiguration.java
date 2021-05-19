/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestClientConfiguration {

    @Bean
    RestTemplate myRestTemplate() {
        return new RestTemplate();
    }

    @Bean
    RestTemplate xsuaaRestOperations() {
        return new RestTemplate();
    }

}
