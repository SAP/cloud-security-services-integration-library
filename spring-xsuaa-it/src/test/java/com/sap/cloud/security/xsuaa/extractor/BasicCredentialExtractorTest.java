/**
 * 
 */
package com.sap.cloud.security.xsuaa.extractor;

import static org.assertj.core.api.Assertions.assertThat;

import javax.servlet.http.HttpServletRequest;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

@RunWith(SpringRunner.class)
@ContextConfiguration(loader = AnnotationConfigContextLoader.class, classes = { XsuaaServiceConfigurationDummy.class,
		TokenBrokerTestConfiguration.class })
public class BasicCredentialExtractorTest {

	private MockHttpServletRequest request;

	@Autowired
	private Cache tokenCache;

	@Autowired
	private TokenBroker tokenBroker;

	@Autowired
	private AuthenticationInformationExtractor authenticationConfiguration;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		request = new MockHttpServletRequest();
	}

	@Test
	public void testBasicCredentialsNoMultiTenancy() {
		TokenBrokerResolver extractor = new TokenBrokerResolver(getXsuaaServiceConfiguration(), tokenCache, tokenBroker,
				authenticationConfiguration);

		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("myuser:mypass".getBytes()));
		String token = extractor.resolve(request);
		assertThat(token).isEqualTo("token_pwd");
	}

	@Test
	public void testBasicCredentialsMultiTenancy() {
		TokenBrokerResolver extractor = new TokenBrokerResolver(getXsuaaServiceConfiguration(), tokenCache, tokenBroker,
				authenticationConfiguration);

		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("myuser:mypass".getBytes()));
		request.addHeader("X-Identity-Zone-Subdomain", "other");
		String token = extractor.resolve(request);
		assertThat(token).isEqualTo("other_token_pwd");
	}

	@Test
	public void testClientCredentials() {
		TokenBrokerResolver extractor = new TokenBrokerResolver(getXsuaaServiceConfiguration(), tokenCache, tokenBroker,
				authenticationMethods(AuthenticationMethod.CLIENT_CREDENTIALS));
		request.addHeader("Authorization",
				"basic " + Base64.getEncoder().encodeToString("client1234:secret1234".getBytes()));
		request.addHeader("X-Identity-Zone-Subdomain", "true");
		request.setScheme("http");
		request.setServerName("t1.cloudfoundry");
		String token = extractor.resolve(request);
		assertThat(token).isEqualTo("token_cc");
	}

	@Test
	public void testOAuth2Credentials() {
		TokenBrokerResolver extractor = new TokenBrokerResolver(getXsuaaServiceConfiguration(), tokenCache, tokenBroker,
				authenticationMethods(AuthenticationMethod.OAUTH2));

		request.addHeader("Authorization", "Bearer "
				+ "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		String token = extractor.resolve(request);
		assertThat(token).isEqualTo(
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidCombinedCredentials() {

		AuthenticationInformationExtractor invalidCombination = new DefaultAuthenticationInformationExtractor() {

			@Override
			public List<AuthenticationMethod> getAuthenticationMethods(HttpServletRequest request) {
				return Arrays.asList(AuthenticationMethod.BASIC, AuthenticationMethod.CLIENT_CREDENTIALS);
			}

		};

		request.addHeader("Authorization", "Bearer "
				+ "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
		TokenBrokerResolver credentialExtractor = new TokenBrokerResolver(getXsuaaServiceConfiguration(), tokenCache,
				tokenBroker, invalidCombination);
		credentialExtractor.resolve(request);
	}

	@Test
	public void testCombinedCredentials() {
		request.addHeader("Authorization", "Bearer "
				+ "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");

		TokenBrokerResolver extractor = new TokenBrokerResolver(getXsuaaServiceConfiguration(), tokenCache, tokenBroker,
				authenticationMethods(AuthenticationMethod.OAUTH2, AuthenticationMethod.BASIC));

		String token = extractor.resolve(request);
		assertThat(token).isEqualTo(
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
	}

	@Test
	public void testCombinedCredentials_shouldTakeBasicAsFallback() {
		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("myuser:mypass".getBytes()));

		TokenBrokerResolver extractor = new TokenBrokerResolver(getXsuaaServiceConfiguration(), tokenCache, tokenBroker,
				authenticationMethods(AuthenticationMethod.BASIC, AuthenticationMethod.OAUTH2));

		String token = extractor.resolve(request);
		assertThat(token).isEqualTo("token_pwd");
	}

	private XsuaaServiceConfiguration getXsuaaServiceConfiguration() {
		XsuaaServiceConfigurationDummy cfg = new XsuaaServiceConfigurationDummy();
		cfg.appId = "a1!123";
		cfg.clientId = "myclient!t1";
		cfg.clientSecret = "top.secret";
		cfg.uaaDomain = "auth.com";
		cfg.uaaUrl = "https://mydomain.auth.com";
		return cfg;
	}

	public AuthenticationInformationExtractor authenticationMethods(AuthenticationMethod... methods) {
		return new DefaultAuthenticationInformationExtractor() {

			@Override
			public List<AuthenticationMethod> getAuthenticationMethods(HttpServletRequest request) {
				return Arrays.asList(methods);
			}
		};

	}
}
