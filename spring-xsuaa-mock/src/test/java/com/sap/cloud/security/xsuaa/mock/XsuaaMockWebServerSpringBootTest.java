/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.mock;

import static org.hamcrest.Matchers.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.mock.autoconfiguration.XsuaaMockAutoConfiguration;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@RunWith(SpringRunner.class)
@ActiveProfiles("uaamock")
@SpringBootTest(classes = { XsuaaMockAutoConfiguration.class })
public class XsuaaMockWebServerSpringBootTest {

	RestTemplate restTemplate = new RestTemplate();

	@Autowired
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Test
	public void xsuaaMockStarted() throws URISyntaxException {
		ResponseEntity<String> response = restTemplate.getForEntity(
				new URI(xsuaaServiceConfiguration.getUaaUrl() + "/token_keys"),
				String.class);
		Assert.assertThat(response.getStatusCode(), equalTo(HttpStatus.OK));
		Assert.assertThat(response.getBody(), notNullValue());
	}

	@Test
	public void xsuaaMockReturnsTestDomainTokenKeys() throws Exception {
		ResponseEntity<String> response = restTemplate
				.getForEntity(new URI(xsuaaServiceConfiguration.getUaaUrl() + "/testdomain/token_keys"), String.class);
		String testdomainTokenKeys = IOUtils.resourceToString("/mock/testdomain_token_keys.json",
				StandardCharsets.UTF_8);
		Assert.assertThat(response.getStatusCode(), equalTo(HttpStatus.OK));
		Assert.assertThat(response.getBody(), containsString("keys"));
		Assert.assertThat(response.getBody(), containsString("legacy-token-key-testdomain"));
		Assert.assertThat(response.getBody(), equalToIgnoringWhiteSpace(testdomainTokenKeys));
	}

	@Test(expected = HttpClientErrorException.class)
	public void xsuaaMockReturnsNotFound() throws URISyntaxException {
		ResponseEntity<String> response = restTemplate
				.getForEntity(new URI(xsuaaServiceConfiguration.getUaaUrl() + "/anyNotSupportedPath"), String.class);
	}

	@Test
	public void xsuaaMockReturnsCustomResponse() throws URISyntaxException {
		ResponseEntity<String> response = restTemplate
				.getForEntity(new URI(xsuaaServiceConfiguration.getUaaUrl() + "/customdomain/token_keys"),
						String.class);
		Assert.assertThat(response.getStatusCode(), equalTo(HttpStatus.OK));
		Assert.assertThat(response.getBody(), containsString("legacy-token-key-customdomain"));
	}
}
