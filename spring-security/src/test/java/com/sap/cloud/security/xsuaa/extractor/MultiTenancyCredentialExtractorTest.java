/**
 * 
 */
package com.sap.cloud.security.xsuaa.extractor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.XsuaaConfiguration;
import com.sap.cloud.security.xsuaa.util.InjectVcapServiceRule;

@RunWith(SpringRunner.class)
@ContextConfiguration(loader = AnnotationConfigContextLoader.class, classes = { XsuaaConfiguration.class })
public class MultiTenancyCredentialExtractorTest {

	private static final String ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.ewogImNsaWVudF9pZCI6ImNsaWVudDEyMzQiLAogImV4cCI6MTUzMTE0MDc3MCwKICJzY29wZSI6WyJqYXZhLWhlbGxvLXdvcmxkLnJlYWQiXSwKICJ1c2VyX25hbWUiOiJ0ZXN0VXNlciIsCiAidXNlcl9pZCI6IjEyMzQiLAogImVtYWlsIjoidGVzdFVzZXJAdGVzdE9yZyIsCiAiemlkIjoiZGVtbyIsCiAiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIgp9.TIwdrvEnMx-CE2Z9_hs0sFVSDPTdkPa_91GvhCNQFc3s4_Mn9ThlXLNUXNNYdYBC9pHFN9ah57vrPtMsNT9pzCFgYxNpVKB7NOA4ZtFVQldaZEQzIoyzOepN2V5TCqQoNR6bJM1gbxeHSTd47E-HNuvO2T9ln__1SC_1OUyUEU7GjZ8gyvtsH3Q8eDmBinTARjfdW7XuND_2SY3NHwkjXsOZiH4pFJm-B-9P7VDLWXZKQf1EFcxPYlVOh2HxHCi2N6sKmkvyr06aTNBJFhavno5Pk88F6nNM0_bVFrfX6a53qeJ0o8ca3uG_7h1IweSh4y0UDtvY5kLR6hCJF4aWzg";

	@ClassRule
	public static InjectVcapServiceRule server = new InjectVcapServiceRule();

	private MockHttpServletRequest request;
	@Autowired
	private XsuaaConfiguration configuration;

	private static final String TOKEN_NAME = "token";

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		request = new MockHttpServletRequest();
	}

	@Bean
	public RestTemplate restTemplate() {
		return Mockito.mock(RestTemplate.class);
	}

	@Bean
	public Cache tokenCache() {
		return new ConcurrentMapCache(TOKEN_NAME);
	}

	@Bean
	public TokenBroker tokenBroker() {

		RestTemplate mockRestTemplate = restTemplate();

		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(ACCESS_TOKEN);
		ResponseEntity<DefaultOAuth2AccessToken> myEntity = new ResponseEntity<DefaultOAuth2AccessToken>(token, HttpStatus.ACCEPTED);
		Mockito.when(mockRestTemplate.exchange(eq("http://t1.localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), ArgumentMatchers.<HttpEntity<MultiValueMap<String, String>>> any(), eq(DefaultOAuth2AccessToken.class))).thenReturn(myEntity);

		return new UaaTokenBroker(mockRestTemplate);
	}

	@Bean
	public AuthenticationInformationExtractor authenticationMethods() {
		return new DefaultAuthenticationInformationExtractor() {

			@Override
			public List<AuthenticationMethod> getAuthenticationMethods(HttpServletRequest request) {
				return Arrays.asList(AuthenticationMethod.CLIENT_CREDENTIALS);
			}
		};

	}

	@Test
	public void testClientCredentials() {
		CredentialExtractor extractor = new CredentialExtractor(configuration, tokenCache(), tokenBroker(), authenticationMethods());
		request.addHeader("Authorization", "basic " + Base64.getEncoder().encodeToString("client1234:secret1234".getBytes()));
		request.addHeader("X-Identity-Zone-Subdomain", "true");
		request.setScheme("http");
		request.setServerName("t1.cloudfoundry");
		Authentication authentication = extractor.extract(request);
		assertThat(authentication.getPrincipal().toString()).isEqualTo(ACCESS_TOKEN);
	}
}
