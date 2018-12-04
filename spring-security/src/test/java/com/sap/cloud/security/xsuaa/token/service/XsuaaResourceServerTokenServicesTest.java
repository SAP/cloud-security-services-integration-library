/**
 * 
 */
package com.sap.cloud.security.xsuaa.token.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import com.sap.cloud.security.xsuaa.api.PostValidationAction;
import com.sap.cloud.security.xsuaa.token.service.exceptions.TokenValidationException;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaResourceServerTokenServicesTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();
	@Mock
	private OfflineTokenValidator offlineTokenValidator;

	private String accessToken = "accessToken";
	private XsuaaResourceServerTokenServices tokenServices;

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
		reset(offlineTokenValidator);
		when(offlineTokenValidator.isApplicable(ArgumentMatchers.<String> any())).thenReturn(true);
		when(offlineTokenValidator.getPostValidationAction(ArgumentMatchers.<Map<String, Object>> any())).thenReturn(new PostValidationAction() {

			@Override
			public boolean apply() {
				return true;
			}
		});
	}

	private Cache tokenCache() {
		return new ConcurrentMapCache("tokenCache");
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	/**
	 * Test method for {@link com.sap.cloud.security.xsuaa.token.service.XsuaaResourceServerTokenServices#loadAuthentication(java.lang.String)}.
	 */
	@Test
	public void loadAuthenticationWithoutValidators() {
		tokenServices = new XsuaaResourceServerTokenServices(tokenCache(), "xsAppName");
		exception.expect(InvalidTokenException.class);
		tokenServices.loadAuthentication("accessTokenValue");
	}

	/**
	 * Test method for {@link com.sap.cloud.security.xsuaa.token.service.XsuaaResourceServerTokenServices#loadAuthentication(java.lang.String)}.
	 */
	@Test
	public void loadAuthenticationWithoutClientId() {
		tokenServices = new XsuaaResourceServerTokenServices(tokenCache(), "xsAppName", offlineTokenValidator);
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("Client id must be present in response from auth server"));
		tokenServices.loadAuthentication(accessToken);
	}

	private Map<String, Object> createResultMap() {
		Map<String, Object> result = new HashMap<>();
		result.put("client_id", "admin");
		result.put("exp", 1535162257L);
		result.put("user_name", "TestUser");
		result.put("scope", Arrays.asList("openid", "testScope", "testApp.localScope"));
		result.put("email", "TestUser@uaa.org");
		result.put("user_id", "d21f5de9-d761-47a2-b6d4-2d83161584d9");

		return result;
	}

	/**
	 * Test method for {@link com.sap.cloud.security.xsuaa.token.service.XsuaaResourceServerTokenServices#loadAuthentication(java.lang.String)}.
	 * 
	 * @throws TokenValidationException
	 */
	@Test
	public void loadAuthentication() throws TokenValidationException {
		Map<String, Object> resultMap = createResultMap();
		when(offlineTokenValidator.validateToken(ArgumentMatchers.<String> any())).thenReturn(resultMap);

		tokenServices = new XsuaaResourceServerTokenServices(tokenCache(), "xsAppName", offlineTokenValidator);
		OAuth2Authentication oAuth2Authentication = tokenServices.loadAuthentication(accessToken);
		assertThat(oAuth2Authentication).isNotNull();
	}

	/**
	 * Test method for {@link com.sap.cloud.security.xsuaa.token.service.XsuaaResourceServerTokenServices#loadAuthentication(java.lang.String)}.
	 * 
	 * @throws TokenValidationException
	 */
	@Test
	public void authenticationCacheWithExpiredAuth() throws TokenValidationException {
		Map<String, Object> resultMap = createResultMap();

		when(offlineTokenValidator.validateToken(ArgumentMatchers.<String> any())).thenReturn(resultMap);

		tokenServices = new XsuaaResourceServerTokenServices(tokenCache(), "xsAppName", offlineTokenValidator);
		OAuth2Authentication oAuth2Authentication = tokenServices.loadAuthentication(accessToken);
		assertThat(oAuth2Authentication).isNotNull();

		tokenServices.loadAuthentication(accessToken);

		verify(offlineTokenValidator, times(2)).validateToken(ArgumentMatchers.<String> any());
	}

	/**
	 * Test method for {@link com.sap.cloud.security.xsuaa.token.service.XsuaaResourceServerTokenServices#loadAuthentication(java.lang.String)}.
	 * 
	 * @throws TokenValidationException
	 */
	@Test
	public void authenticationCaching() throws TokenValidationException {
		Map<String, Object> resultMap = createResultMap();
		resultMap.put("exp", (new Date()).getTime() + 3000L);

		when(offlineTokenValidator.validateToken(ArgumentMatchers.<String> any())).thenReturn(resultMap);

		tokenServices = new XsuaaResourceServerTokenServices(tokenCache(), new TenantAuthorizationMapper(), "xsAppName", offlineTokenValidator);
		OAuth2Authentication oAuth2Authentication = tokenServices.loadAuthentication(accessToken);
		assertThat(oAuth2Authentication).isNotNull();

		tokenServices.loadAuthentication(accessToken);

		verify(offlineTokenValidator, times(1)).validateToken(ArgumentMatchers.<String> any());
	}

	/**
	 * Test method for {@link com.sap.cloud.security.xsuaa.token.service.XsuaaResourceServerTokenServices#readAccessToken(java.lang.String)}.
	 */
	@Test
	public void readAccessToken() {
	}
}
