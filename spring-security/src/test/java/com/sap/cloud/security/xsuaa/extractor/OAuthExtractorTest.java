/**
 * 
 */
package com.sap.cloud.security.xsuaa.extractor;


import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

import com.sap.cloud.security.xsuaa.XsuaaConfiguration;
import com.sap.cloud.security.xsuaa.extractor.intern.TokenBrokerConfiguration;
import com.sap.cloud.security.xsuaa.util.InjectVcapServiceRule;


@RunWith(SpringRunner.class)
@ContextConfiguration(loader = AnnotationConfigContextLoader.class, classes = { XsuaaConfiguration.class, TokenBrokerConfiguration.class })
public class OAuthExtractorTest {

	@ClassRule
	public static InjectVcapServiceRule server = new InjectVcapServiceRule();

	private MockHttpServletRequest request;

	@Autowired
	private XsuaaConfiguration configuration;

	@Autowired
	private Cache tokenCache;

	@Autowired
	private TokenBroker tokenBroker;

	@Autowired
	private AuthenticationInformationExtractor authenticationConfiguration;

	@Bean
	public CredentialExtractor extractor() {
		return new CredentialExtractor(configuration, tokenCache, tokenBroker, authenticationConfiguration);
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
	public void testOAuth2Credentials() {
		request.addHeader("Authorization", "Bearer " + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		Authentication authentication = extractor().extract(request);
		assertThat(authentication.getPrincipal().toString()).isEqualTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidCombinedCredentials() {

		AuthenticationInformationExtractor invalidCombination = new DefaultAuthenticationInformationExtractor() {

			@Override
			public List<AuthenticationMethod> getAuthenticationMethods(HttpServletRequest request) {
				return Arrays.asList(AuthenticationMethod.BASIC, AuthenticationMethod.CLIENT_CREDENTIALS);
			}

		};

		request.addHeader("Authorization", "Bearer " + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		CredentialExtractor credentialExtractor = new CredentialExtractor(configuration, tokenCache, tokenBroker, invalidCombination);
		credentialExtractor.extract(request);
	}

	@Test
	public void combinedCredentials() {
		request.addHeader("Authorization", "Bearer " + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");

		CredentialExtractor extractor = new CredentialExtractor(configuration, tokenCache, tokenBroker, authenticationConfiguration);

		Authentication authentication = extractor.extract(request);
		assertThat(authentication.getPrincipal().toString()).isEqualTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
	}

}
