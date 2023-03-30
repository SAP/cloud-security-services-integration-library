/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthenticationInformationExtractorTest {

	private MockHttpServletRequest request;
	private AuthenticationInformationExtractor authenticationConfiguration;

	@Before
	public void setUp() {
		request = new MockHttpServletRequest();
		authenticationConfiguration = authenticationConfiguration();
	}

	public AuthenticationInformationExtractor authenticationConfiguration() {
		return new DefaultAuthenticationInformationExtractor();
	}

	/**
	 * Test method for
	 * {@link com.sap.cloud.security.xsuaa.extractor.AuthenticationInformationExtractor#getSubdomain(jakarta.servlet.http.HttpServletRequest)}.
	 */
	@Test(expected = RuntimeException.class)
	public void getSubdomainWithoutRequest() {
		Optional<String> subdomain = authenticationConfiguration.getSubdomain(null);
		assertThat(subdomain).isEmpty();
	}

	/**
	 * Test method for
	 * {@link com.sap.cloud.security.xsuaa.extractor.AuthenticationInformationExtractor#getSubdomain(jakarta.servlet.http.HttpServletRequest)}.
	 */
	@Test
	public void withoutSubdomainParameters() {
		Optional<String> subdomain = authenticationConfiguration.getSubdomain(request);
		assertThat(subdomain).isEmpty();
	}

	/**
	 * Test method for
	 * {@link com.sap.cloud.security.xsuaa.extractor.AuthenticationInformationExtractor#getSubdomain(jakarta.servlet.http.HttpServletRequest)}.
	 */
	@Test
	public void validSubDomain() {
		request.addParameter("X-Identity-Zone-Subdomain", "t1");

		Optional<String> subdomain = authenticationConfiguration.getSubdomain(request);
		assertThat(subdomain).hasValue("t1");
	}

	/**
	 * Test method for
	 * {@link com.sap.cloud.security.xsuaa.extractor.AuthenticationInformationExtractor#getAuthenticationMethods(jakarta.servlet.http.HttpServletRequest)}.
	 */
	@Test
	public void getAuthenticationMethods() {
		List<AuthenticationMethod> authenticationMethods = authenticationConfiguration.getAuthenticationMethods(null);
		assertThat(authenticationMethods).contains(AuthenticationMethod.BASIC, AuthenticationMethod.OAUTH2);
	}

}
