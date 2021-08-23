/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import org.apache.commons.io.IOUtils;
import org.assertj.core.api.Assertions;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static com.sap.cloud.security.config.cf.CFConstants.Plan.BROKER;
import static java.nio.charset.StandardCharsets.UTF_8;

public class CFEnvParserXsuaaTest {

	private OAuth2ServiceConfiguration cut;

	public CFEnvParserXsuaaTest() throws IOException {
		String vcapXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);

		JsonObject serviceJsonObject = new DefaultJsonObject(vcapXsuaa).getJsonObjects(Service.XSUAA.getCFName())
				.get(0);
		cut = CFEnvParser.loadForService(Service.XSUAA, serviceJsonObject);
	}

	@Test
	public void getClientId() {
		Assertions.assertThat(cut.getClientId()).isEqualTo("clientId");
	}

	@Test
	public void getClientSecret() {
		Assertions.assertThat(cut.getClientSecret()).isEqualTo("secret");
	}

	@Test
	public void getUrl() {
		Assertions.assertThat(cut.getUrl()).isEqualTo(URI.create("https://paastenant.auth.com"));
	}

	@Test
	public void getDomain() {
		Assertions.assertThat(cut.getProperty(XSUAA.UAA_DOMAIN)).isEqualTo("auth.com");
	}

	@Test
	public void getDomains() {
		Assertions.assertThat(cut.getDomains()).isEqualTo(Collections.emptyList());
	}

	@Test
	public void getProperty() {
		Assertions.assertThat(cut.getProperty("xsappname")).isEqualTo("java-hello-world");
	}

	@Test
	public void getPlan() {
		Assertions.assertThat(cut.getProperty(SERVICE_PLAN)).isEqualToIgnoringCase("broker");
		Assertions.assertThat(Plan.from(cut.getProperty(SERVICE_PLAN))).isEqualTo(BROKER);
	}

	@Test
	public void getService() {
		Assertions.assertThat(cut.getService()).isEqualTo(Service.XSUAA);
	}

}