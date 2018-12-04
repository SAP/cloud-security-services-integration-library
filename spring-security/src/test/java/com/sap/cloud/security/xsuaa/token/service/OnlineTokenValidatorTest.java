/**
 * 
 */
package com.sap.cloud.security.xsuaa.token.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.XsuaaConfiguration;
import com.sap.cloud.security.xsuaa.util.JWTUtil;

@RunWith(MockitoJUnitRunner.class)
public class OnlineTokenValidatorTest {

	private static final String IDENTITY_ZONE = "paas";

	private static final String TOKEN_CLIENT_ID = "tokenClient-Id";

	@Mock
	RestTemplate restTemplate;
	@Mock
	RestTemplate restTemplateMultiTenancy;
	@Mock
	XsuaaConfiguration configuration;

	private Map<String, Object> result;

	private final String samplePublicKey = "-----BEGIN PUBLIC KEY-----\n" + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4g5rJQuuAcjLy5vqirFN3MnFB\n" + "bD6SgUAq8zmmSoxFexd6xXyXSnVib22HmARXKx1oEwFyKaCBXgLNX87enipdxRBi\n" + "DAyxYPOFGeyZ1lCu/WZU/5+JP2CZDFtqtLdpr+Ibhbznktx21v7EzhCiaANLWy59\n" + "Wx8PGdRyZeJ7Q8oRXwIDAQAB\n" + "-----END PUBLIC KEY-----";
	private final String samplePrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" + "MIICXAIBAAKBgQC4g5rJQuuAcjLy5vqirFN3MnFBbD6SgUAq8zmmSoxFexd6xXyX\n" + "SnVib22HmARXKx1oEwFyKaCBXgLNX87enipdxRBiDAyxYPOFGeyZ1lCu/WZU/5+J\n" + "P2CZDFtqtLdpr+Ibhbznktx21v7EzhCiaANLWy59Wx8PGdRyZeJ7Q8oRXwIDAQAB\n" + "AoGBAKm1MgrnKCBN6RqM4/33LhW2KYEZBDxP8SsP5vhSHM5TNvdO6Rdl/q14+275\n" + "nRRnrXZp9KyCKQST6VPoSSdspl1hKomL2NcjJQWiyDckFvGQ6yoaP/IF51GqQgD8\n" + "oAW0y1SEVyaHyEXeWaGO0iw69ekV/mBzg/AYcOhrgRXElitxAkEA+WO7+uLwYxY6\n" + "OP31COGVXFXv9Y+kRS4nVsVG7InWpJ32nEgLnv0b53SSTislM1oQSndVj2e0fmQI\n" + "gxuoBT0EIwJBAL1npirWuJdXaDe5a7rqsF9Td6Bp7fBqLvlTzhViTbiftlJd9KqI\n" + "NV9oW468j4W8SFMmLag1sex1exn0pRBgw5UCQHwPq0HhhygjtI8Jds4WOlEWxypn\n" + "bJaloRg/R0sAPvDhS/7usClFTI5VpTqRqA3lrdj9iGiwdE+zv7BJH8qLUfUCQCqR\n" + "ReYw1dGlolWLxat/nV3/O06BICm9I4uDiziBHGiW9Hn0hc1hyWUE5jbhJ/xtgW+2\n" + "j+JTFwbGrID727EfnjUCQGHhgtmg9nYgsjZjysaGO6D8FX1/mrBj4RQfFg8umjAw\n" + "R9+wQFv0JPcUHgIlLti9Sv6GbdstE/uYGxYGGXiwNx4=\n"
			+ "-----END RSA PRIVATE KEY-----";

	private OnlineTokenValidator tokenValidator;
	private String accessToken;

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
		Mockito.when(configuration.getUaaUrl()).thenReturn("http://localhost:8080/uaa");
		when(configuration.getClientId()).thenReturn(TOKEN_CLIENT_ID);
		when(configuration.getIdentityZoneId()).thenReturn(IDENTITY_ZONE);
		when(configuration.getUaadomain()).thenReturn("localhost:8080/uaa");

		result = new LinkedHashMap<>();
		result.put("client_id", TOKEN_CLIENT_ID);
		result.put("exp", System.currentTimeMillis() / 1000 + 3);
		result.put("jti", "7dda652432324b6281b2d18e926bc363");
		result.put("grant_type", "client_credentials");
		result.put("zid", IDENTITY_ZONE);

		ResponseEntity<Map> myEntity = new ResponseEntity<Map>(result, HttpStatus.ACCEPTED);
		Mockito.when(restTemplate.exchange(eq("http://localhost:8080/uaa/check_token"), eq(HttpMethod.POST), ArgumentMatchers.<HttpEntity<MultiValueMap<String, Object>>> any(), eq(Map.class))).thenReturn(myEntity);

		tokenValidator = new OnlineTokenValidator(configuration, restTemplate);

		accessToken = JWTUtil.createJWT(TOKEN_CLIENT_ID, samplePrivateKey);
	}
	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	/**
	 * Test method for {@link com.sap.cloud.security.xsuaa.token.service.OnlineTokenValidator#validateToken(java.lang.String)}.
	 * 
	 * @throws Exception
	 */
	@Test
	public void validateToken() throws Exception {
		Map<String, Object> tokenInfo = tokenValidator.validateToken(accessToken);
		assertThat(tokenInfo).isNotEmpty();
	}

	/**
	 * Test method for {@link com.sap.cloud.security.xsuaa.token.service.OnlineTokenValidator#validateToken(java.lang.String)}.
	 * 
	 * @throws Exception
	 */
	@Test
	public void validateTokenInMultiTenancyCase() throws Exception {

		ResponseEntity<Map> myEntity = new ResponseEntity<Map>(result, HttpStatus.ACCEPTED);
		Mockito.when(restTemplateMultiTenancy.exchange(eq("http://paas.localhost:8080/uaa/check_token"), eq(HttpMethod.POST), ArgumentMatchers.<HttpEntity<MultiValueMap<String, Object>>> any(), eq(Map.class))).thenReturn(myEntity);

		String accessTokenMultiTenancy = JWTUtil.createMultiTenancyJWT(TOKEN_CLIENT_ID, samplePrivateKey);

		tokenValidator = new OnlineTokenValidator(configuration, restTemplateMultiTenancy);
		Map<String, Object> tokenInfo = tokenValidator.validateToken(accessTokenMultiTenancy);
		assertThat(tokenInfo).isNotEmpty();
	}

	/**
	 * Test method for {@link com.sap.cloud.security.xsuaa.token.service.OnlineTokenValidator#isApplicable(java.lang.String)}.
	 */
	@Test
	public void isApplicableOpaque() {
		boolean applicable = tokenValidator.isApplicable("opaqueToken");
		assertThat(applicable).isTrue();
	}

	/**
	 * Test method for {@link com.sap.cloud.security.xsuaa.token.service.OnlineTokenValidator#isApplicable(java.lang.String)}.
	 */
	@Test
	public void isApplicable() {
		boolean applicable = tokenValidator.isApplicable(accessToken);
		assertThat(applicable).isTrue();
	}

}
