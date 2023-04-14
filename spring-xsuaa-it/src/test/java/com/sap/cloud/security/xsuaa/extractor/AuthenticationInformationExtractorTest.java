/**
 * 
 */
/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p> 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

public class AuthenticationInformationExtractorTest {

	private MockHttpServletRequest request;
	private AuthenticationInformationExtractor authenticationConfiguration;

	/**
	 * @throws java.lang.Exception
	 */
	@BeforeClass
	public static void setUpBeforeClass() {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@AfterClass
	public static void tearDownAfterClass() {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		request = new MockHttpServletRequest();
		authenticationConfiguration = authenticationConfiguration();
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() {
	}

	public AuthenticationInformationExtractor authenticationConfiguration() {
		return new DefaultAuthenticationInformationExtractor();
	}

	/**
	 * Test method for
	 * {@link com.sap.cloud.security.xsuaa.extractor.AuthenticationInformationExtractor#getSubdomain(javax.servlet.http.HttpServletRequest)}.
	 */
	@Test(expected = RuntimeException.class)
	public void getSubdomainWithoutRequest() {
		Optional<String> subdomain = authenticationConfiguration.getSubdomain(null);
		assertThat(subdomain).isEmpty();
	}

	/**
	 * Test method for
	 * {@link com.sap.cloud.security.xsuaa.extractor.AuthenticationInformationExtractor#getSubdomain(javax.servlet.http.HttpServletRequest)}.
	 */
	@Test
	public void withoutSubdomainParameters() {
		Optional<String> subdomain = authenticationConfiguration.getSubdomain(request);
		assertThat(subdomain).isEmpty();
	}

	/**
	 * Test method for
	 * {@link com.sap.cloud.security.xsuaa.extractor.AuthenticationInformationExtractor#getSubdomain(javax.servlet.http.HttpServletRequest)}.
	 */
	@Test
	public void validSubDomain() {
		request.addParameter("X-Identity-Zone-Subdomain", "t1");

		Optional<String> subdomain = authenticationConfiguration.getSubdomain(request);
		assertThat(subdomain).hasValue("t1");
	}

	/**
	 * Test method for
	 * {@link com.sap.cloud.security.xsuaa.extractor.AuthenticationInformationExtractor#getAuthenticationMethods(javax.servlet.http.HttpServletRequest)}.
	 */
	@Test
	public void getAuthenticationMethods() {
		List<AuthenticationMethod> authenticationMethods = authenticationConfiguration.getAuthenticationMethods(null);
		assertThat(authenticationMethods).contains(AuthenticationMethod.BASIC, AuthenticationMethod.OAUTH2);
	}

}
