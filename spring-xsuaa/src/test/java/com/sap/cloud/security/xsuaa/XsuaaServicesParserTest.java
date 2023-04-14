/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.cf.CFConstants.XSUAA;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

public class XsuaaServicesParserTest {

	@Test
	public void ignoreApiAccessPlan() throws IOException {
		String vcapMultipleBindings = IOUtils.resourceToString("/vcap_multipleBindings.json", StandardCharsets.UTF_8);
		XsuaaServicesParser cut = new XsuaaServicesParser(vcapMultipleBindings);
		Properties properties = cut.parseCredentials();
		assertThat(properties.getProperty(CFConstants.CLIENT_ID)).isEqualTo("client-id");
	}

	@Test(expected = IllegalStateException.class)
	public void doNotAllowBrokerAndApplicationPlan() throws IOException {
		String vcapMultipleBindings = IOUtils.resourceToString("/vcap_multipleBindings.json", StandardCharsets.UTF_8);
		vcapMultipleBindings = vcapMultipleBindings.replace("apiaccess", "broker");
		XsuaaServicesParser cut = new XsuaaServicesParser(vcapMultipleBindings);
		cut.parseCredentials();
	}

	@Test
	public void acceptVcapServicesWithoutPlan() throws IOException {
		String vcapMinimalWoPlan = "{\"xsuaa\":[{\"credentials\":{\"clientid\":\"client-id\",\"clientsecret\":\"client-secret\"},\"tags\":[\"xsuaa\"]}]}";
		XsuaaServicesParser cut = new XsuaaServicesParser(vcapMinimalWoPlan);
		Properties properties = cut.parseCredentials();
		assertThat(properties.getProperty(CFConstants.CLIENT_ID)).isEqualTo("client-id");
	}

	@Test
	public void acceptOtherVcapServicesProperties() throws IOException {
		String vcapWithAddProperties = "{\"xsuaa\":[{\"credentials\":{\"apiurl\":\"https://api.mydomain.com\",\"tenantid\":\"tenant-id\",\"subaccountid\":\"subaccount-id\",\"clientid\":\"client-id\"},\"tags\":[\"xsuaa\"]}]}";
		XsuaaServicesParser cut = new XsuaaServicesParser(vcapWithAddProperties);
		Properties properties = cut.parseCredentials();
		assertThat(properties.getProperty(XSUAA.API_URL)).isEqualTo("https://api.mydomain.com");
		assertThat(properties.containsKey(XSUAA.API_URL)).isTrue();
		assertThat(properties.getProperty(XSUAA.SUBACCOUNT_ID)).isEqualTo("subaccount-id");
		assertThat(properties.containsKey(XSUAA.SUBACCOUNT_ID)).isTrue();
		assertThat(properties.getProperty(XSUAA.TENANT_ID)).isEqualTo("tenant-id");
		assertThat(properties.getProperty(CFConstants.CLIENT_ID)).isEqualTo("client-id");
	}
}
