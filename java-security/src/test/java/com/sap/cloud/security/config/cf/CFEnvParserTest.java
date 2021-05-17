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
import org.junit.Test;

import java.io.IOException;
import java.net.URI;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static com.sap.cloud.security.config.cf.CFConstants.Plan.BROKER;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class CFEnvParserTest {

	private OAuth2ServiceConfiguration cut;

	public CFEnvParserTest() throws IOException {
		String vcapXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);

		JsonObject serviceJsonObject = new DefaultJsonObject(vcapXsuaa).getJsonObjects(Service.XSUAA.getCFName())
				.get(0);
		cut = CFEnvParser.loadForService(Service.XSUAA, serviceJsonObject);
	}

	@Test
	public void getClientId() {
		assertThat(cut.getClientId()).isEqualTo("clientId");
	}

	@Test
	public void getClientSecret() {
		assertThat(cut.getClientSecret()).isEqualTo("secret");
	}

	@Test
	public void getUrl() {
		assertThat(cut.getUrl()).isEqualTo(URI.create("https://paastenant.auth.com"));
	}

	@Test
	public void getDomain() {
		assertThat(cut.getProperty(XSUAA.UAA_DOMAIN)).isEqualTo("auth.com");
	}

	@Test
	public void getProperty() {
		assertThat(cut.getProperty("xsappname")).isEqualTo("java-hello-world");
	}

	@Test
	public void getPlan() {
		assertThat(cut.getProperty(SERVICE_PLAN)).isEqualTo("broker");
		assertThat(Plan.from(cut.getProperty(SERVICE_PLAN))).isEqualTo(BROKER);
	}

	@Test
	public void getService() {
		assertThat(cut.getService()).isEqualTo(Service.XSUAA);
	}

}