/**
 * 
 */
package com.sap.cloud.security.xsuaa.extractor;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;

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
import com.sap.cloud.security.xsuaa.util.InjectVcapServiceRule;

@RunWith(SpringRunner.class)
@ContextConfiguration(loader = AnnotationConfigContextLoader.class, classes = { XsuaaConfiguration.class, TokenBrokerTestConfiguration.class })
public class BasicCredentialExtractorTest {

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
	public void testBasicCredentials() {
		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("client123:secret123".getBytes()));
		Authentication authentication = extractor().extract(request);
		assertThat(authentication.getPrincipal().toString()).isEqualTo("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.ewogImNsaWVudF9pZCI6InhzMi51c2VydG9rZW4iLAogImV4cCI6MTUzMTE0MDc3MCwKICJzY29wZSI6WyJqYXZhLWhlbGxvLXdvcmxkLnJlYWQiXSwKICJ1c2VyX25hbWUiOiJ0ZXN0VXNlciIsCiAidXNlcl9pZCI6IjEyMzQiLAogImVtYWlsIjoidGVzdFVzZXJAdGVzdE9yZyIsCiAiemlkIjoiZGVtbyIsCiAiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIgp9.NPEW2Qc1ptRJiq6H7h4KwGJEFbYgeF4rqjB4-8bTtOExUMZwiOeR-bzE2MXwBN1C_1BhMgnemAzEG_4yLwIGckNcZ2_ojJUYOiuuFiLWxrTCqbZa35ta2teINErTZhX_elBnMlzj5mmTy3gNFLPMZE5g8zU_D-k79s6lWmGckpnulYK2J6Vl9mBlTIG2sSnizWn67yAFzsIhWtgkuMlLb0WjM4wRNFWEpRf06hbyypcWeyYAWJAcq9guE2kx2RRITk3_kc6JFUIYSAbxnWpD4YBdBsFoQlu1nIfGcJxW6lWLGArkD0mxSllbofsHegQuXECnNeP6xLpVOVRaQ01gFA");
	}

}
