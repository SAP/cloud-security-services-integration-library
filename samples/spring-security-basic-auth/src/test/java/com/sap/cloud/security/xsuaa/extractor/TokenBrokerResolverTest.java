/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = { TokenBrokerTestConfiguration.class })
public class TokenBrokerResolverTest {
	private static final String XSUAA_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHRfYXR0ciI6eyJlbmhhbmNlciI6IlhTVUFBIn19._cocFCqqATDXx6eBUoF22W9F8VwUVYY59XdLGdEDFso";

	@Autowired
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;
	@Autowired
	private OAuth2TokenService oAuth2TokenService;
	@Autowired
	private AuthenticationInformationExtractor authenticationConfiguration;

	private MockHttpServletRequest request;
	private static TokenBrokerResolver tokenBroker;

	@BeforeEach
	void setUp() {
		request = new MockHttpServletRequest();
		tokenBroker = new TokenBrokerResolver(xsuaaServiceConfiguration, null,
				oAuth2TokenService,
				authenticationConfiguration);
	}

	@Test
	void xsuaaTokenResolutionTest() {
		request.addHeader("Authorization", "bearer " + XSUAA_TOKEN);
		String token = tokenBroker.resolve(request);

		assertThat(token).isEqualTo(XSUAA_TOKEN);
	}
}
