/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(loader = AnnotationConfigContextLoader.class, classes = { TokenBrokerTestConfiguration.class })
public class BasicCredentialExtractorTest {

	private MockHttpServletRequest request;

	@Autowired
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Autowired
	private Cache tokenCache;

	@Autowired
	private OAuth2TokenService oAuth2TokenService;

	@Autowired
	private AuthenticationInformationExtractor authenticationConfiguration;

	private static final String XSUAA_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHRfYXR0ciI6eyJlbmhhbmNlciI6IlhTVUFBIn19._cocFCqqATDXx6eBUoF22W9F8VwUVYY59XdLGdEDFso";

	@BeforeEach
	void setUp() {
		request = new MockHttpServletRequest();
	}

	@Test
	void testBasicCredentialsNoMultiTenancy() {
		TokenBrokerResolver extractor = new TokenBrokerResolver(xsuaaServiceConfiguration, tokenCache,
				oAuth2TokenService,
				authenticationConfiguration);

		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("myuser:mypass".getBytes()));
		String token = extractor.resolve(request);
		assertThat(token).isEqualTo("token_pwd");
	}

	@Test
	void testBasicCredentialsMultiTenancy() {
		TokenBrokerResolver extractor = new TokenBrokerResolver(xsuaaServiceConfiguration, tokenCache,
				oAuth2TokenService,
				authenticationConfiguration);

		request.addHeader("X-Identity-Zone-Subdomain", "other");
		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("myuser:mypass".getBytes()));

		String token = extractor.resolve(request);
		assertThat(token).isEqualTo("other_token_pwd");
	}

	@Test
	void testMultipleAuthorizationHeaders_useMatchOfFirstMethod() {
		TokenBrokerResolver extractor = new TokenBrokerResolver(xsuaaServiceConfiguration, tokenCache,
				oAuth2TokenService,
				authenticationConfiguration);

		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("myuser:mypass".getBytes()));
		request.addHeader("Authorization", "bearer "
				+ "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHRfYXR0ciI6eyJlbmhhbmNlciI6IlhTVUFBIn19._cocFCqqATDXx6eBUoF22W9F8VwUVYY59XdLGdEDFso");

		String token = extractor.resolve(request);
		assertThat(token).isEqualTo("token_pwd");

		// Change order of configured methods
		extractor.setAuthenticationConfig(
				new DefaultAuthenticationInformationExtractor(AuthenticationMethod.OAUTH2, AuthenticationMethod.BASIC));
		token = extractor.resolve(request);
		assertThat(token).startsWith("eyJhbGciOiJIUzI1N");
	}

	@Test
	void testMultipleAuthorizationHeaders_useSecondMethod() {
		TokenBrokerResolver extractor = new TokenBrokerResolver(xsuaaServiceConfiguration, tokenCache,
				oAuth2TokenService,
				new DefaultAuthenticationInformationExtractor(AuthenticationMethod.OAUTH2,
						AuthenticationMethod.CLIENT_CREDENTIALS));

		request.addHeader("Authorization",
				"basic " + Base64.getEncoder().encodeToString("client1234:secret1234".getBytes()));

		String token = extractor.resolve(request);
		assertThat(token).isEqualTo("token_client1234");
	}

	@Test
	void testMultipleBasicAuthorizationHeaders_useSecond() {
		TokenBrokerResolver extractor = new TokenBrokerResolver(xsuaaServiceConfiguration, tokenCache,
				oAuth2TokenService,
				authenticationConfiguration);

		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("myuser".getBytes()));
		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("myuser:mypass".getBytes()));

		request.addHeader("X-Identity-Zone-Subdomain", "other");
		String token = extractor.resolve(request);
		assertThat(token).isEqualTo("other_token_pwd");
	}

	@Test
	void testClientCredentials() {
		TokenBrokerResolver extractor = new TokenBrokerResolver(xsuaaServiceConfiguration, tokenCache,
				oAuth2TokenService,
				authenticationMethods(AuthenticationMethod.CLIENT_CREDENTIALS));
		request.addHeader("Authorization",
				"basic " + Base64.getEncoder().encodeToString("client1234:secret1234".getBytes()));
		request.addHeader("X-Identity-Zone-Subdomain", "x-idz-subdomain");
		request.setScheme("http");
		request.setServerName("t1.cloudfoundry");
		String token = extractor.resolve(request);
		assertThat(token).isEqualTo("token_client1234");
	}

	@Test
	void testOAuth2Credentials() {
		TokenBrokerResolver extractor = new TokenBrokerResolver(xsuaaServiceConfiguration, tokenCache,
				oAuth2TokenService,
				authenticationMethods(AuthenticationMethod.OAUTH2));

		request.addHeader("Authorization", "Bearer "
				+ XSUAA_TOKEN);
		String token = extractor.resolve(request);
		assertThat(token).isEqualTo(
				XSUAA_TOKEN);
	}

	@Test
	void testInvalidCombinedCredentials() {
		AuthenticationInformationExtractor invalidCombination = new DefaultAuthenticationInformationExtractor() {

			@Override
			public List<AuthenticationMethod> getAuthenticationMethods(HttpServletRequest request) {
				return Arrays.asList(AuthenticationMethod.BASIC, AuthenticationMethod.CLIENT_CREDENTIALS);
			}

		};

		request.addHeader("Authorization", "Bearer "
				+ "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		TokenBrokerResolver credentialExtractor = new TokenBrokerResolver(xsuaaServiceConfiguration, tokenCache,
				oAuth2TokenService, invalidCombination);

		Assertions.assertThrows(IllegalArgumentException.class, () -> credentialExtractor.resolve(request));
	}

	@Test
	void testCombinedCredentials() {
		request.addHeader("Authorization", "Bearer "
				+ XSUAA_TOKEN);

		TokenBrokerResolver extractor = new TokenBrokerResolver(xsuaaServiceConfiguration, tokenCache,
				oAuth2TokenService,
				authenticationMethods(AuthenticationMethod.OAUTH2, AuthenticationMethod.BASIC));

		String token = extractor.resolve(request);
		assertThat(token).isEqualTo(
				XSUAA_TOKEN);
	}

	@Test
	void testCombinedCredentials_shouldTakeBasicAsFallback() {
		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("myuser:mypass".getBytes()));

		TokenBrokerResolver extractor = new TokenBrokerResolver(xsuaaServiceConfiguration, tokenCache,
				oAuth2TokenService,
				authenticationMethods(AuthenticationMethod.BASIC, AuthenticationMethod.OAUTH2));

		String token = extractor.resolve(request);
		assertThat(token).isEqualTo("token_pwd");
	}

	private AuthenticationInformationExtractor authenticationMethods(AuthenticationMethod... methods) {
		return new DefaultAuthenticationInformationExtractor() {

			@Override
			public List<AuthenticationMethod> getAuthenticationMethods(HttpServletRequest request) {
				return Arrays.asList(methods);
			}
		};

	}
}
