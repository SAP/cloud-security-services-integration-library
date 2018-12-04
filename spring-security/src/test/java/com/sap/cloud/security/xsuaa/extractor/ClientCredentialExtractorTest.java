/**
 * 
 */
package com.sap.cloud.security.xsuaa.extractor;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

import com.sap.cloud.security.xsuaa.XsuaaConfiguration;
import com.sap.cloud.security.xsuaa.util.InjectVcapServiceRule;
@RunWith(SpringRunner.class)
@ContextConfiguration(loader = AnnotationConfigContextLoader.class, classes = { XsuaaConfiguration.class, TokenBrokerTestConfiguration.class })
public class ClientCredentialExtractorTest {

	@ClassRule
	public static InjectVcapServiceRule server = new InjectVcapServiceRule();

	private MockHttpServletRequest request;
	@Autowired
	private XsuaaConfiguration configuration;

	@Autowired
	private Cache tokenCache;

	@Autowired
	private TokenBroker tokenBroker;
	
	@Bean
	@Primary
	public AuthenticationInformationExtractor authenticationMethods() {
		return new DefaultAuthenticationInformationExtractor() {

			@Override
			public List<AuthenticationMethod> getAuthenticationMethods(HttpServletRequest request) {
				return Arrays.asList(AuthenticationMethod.CLIENT_CREDENTIALS);
			}

		};

	}


	/**
	 * @throws java.lang.Exception
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		request = new MockHttpServletRequest();
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}


	@Test
	public void testClientCredentials() {
		CredentialExtractor extractor = new CredentialExtractor(configuration, tokenCache, tokenBroker, authenticationMethods());
		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("client1234:secret1234".getBytes()));
		Authentication authentication = extractor.extract(request);
		System.out.println(authentication.getPrincipal().toString());
		assertThat(authentication.getPrincipal().toString()).isEqualTo(
				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.ewogImNsaWVudF9pZCI6ImNsaWVudDEyMzQiLAogImV4cCI6MTUzMTE0MDc3MCwKICJzY29wZSI6WyJqYXZhLWhlbGxvLXdvcmxkLnJlYWQiXSwKICJ1c2VyX25hbWUiOiJ0ZXN0VXNlciIsCiAidXNlcl9pZCI6IjEyMzQiLAogImVtYWlsIjoidGVzdFVzZXJAdGVzdE9yZyIsCiAiemlkIjoiZGVtbyIsCiAiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIgp9.TIwdrvEnMx-CE2Z9_hs0sFVSDPTdkPa_91GvhCNQFc3s4_Mn9ThlXLNUXNNYdYBC9pHFN9ah57vrPtMsNT9pzCFgYxNpVKB7NOA4ZtFVQldaZEQzIoyzOepN2V5TCqQoNR6bJM1gbxeHSTd47E-HNuvO2T9ln__1SC_1OUyUEU7GjZ8gyvtsH3Q8eDmBinTARjfdW7XuND_2SY3NHwkjXsOZiH4pFJm-B-9P7VDLWXZKQf1EFcxPYlVOh2HxHCi2N6sKmkvyr06aTNBJFhavno5Pk88F6nNM0_bVFrfX6a53qeJ0o8ca3uG_7h1IweSh4y0UDtvY5kLR6hCJF4aWzg");
	}

}
