/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.URI;

import org.junit.Test;

public class XsuaaTokenFlowRequestTest {

	@Test
	public void initialize() {
		XsuaaTokenFlowRequest request = new XsuaaTokenFlowRequest(URI.create("https://oauth.server.com/oauth/token"));
		String clientId = "clientId";
		String clientSecret = "clientSecret";
		String zoneId = "zone";

		request.setClientId(clientId);
		request.setClientSecret(clientSecret);
		request.setZoneId(zoneId);

		assertThat(request.getTokenEndpoint().toString(), is("https://oauth.server.com/oauth/token"));
		assertThat(request.getClientId(), is(clientId));
		assertThat(request.getClientSecret(), is(clientSecret));
		assertThat(request.getZoneId(), is(zoneId));
	}
}
