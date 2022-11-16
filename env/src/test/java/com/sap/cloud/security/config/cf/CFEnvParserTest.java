/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
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
import static com.sap.cloud.security.config.cf.CFConstants.Plan.APPLICATION;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class CFEnvParserTest {

	private OAuth2ServiceConfiguration cut;

	public CFEnvParserTest() throws IOException {
		String vcapIas = IOUtils.resourceToString("/vcapIasServiceSingleBinding.json", UTF_8);

		JsonObject serviceJsonObject = new DefaultJsonObject(vcapIas).getJsonObjects(Service.IAS.getCFName())
				.get(0);
		cut = CFEnvParser.loadForService(Service.IAS, serviceJsonObject);
	}

	@Test
	public void getClientId() {
		assertThat(cut.getClientId()).isEqualTo("T000310");
	}

	@Test
	public void getClientSecret() {
		assertThat(cut.getClientSecret()).isEqualTo("pCghfbrLudwzXM2fPq7YSIhujAmpHj_I0DeMKHKRAqs=");
	}

	@Test
	public void getUrl() {
		assertThat(cut.getUrl()).isEqualTo(URI.create("https://myauth.com"));
	}

	@Test
	public void getDomains() {
		assertThat(cut.getDomains()).contains("myauth.com", "my.auth.com");
	}

	@Test
	public void getPlan() {
		assertThat(cut.getProperty(SERVICE_PLAN)).isEqualTo("application");
		assertThat(Plan.from(cut.getProperty(SERVICE_PLAN))).isEqualTo(APPLICATION);
	}

	@Test
	public void getService() {
		assertThat(cut.getService()).isEqualTo(Service.IAS);
	}

}