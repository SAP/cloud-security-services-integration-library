package com.sap.cloud.security.samples;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.servlet.OAuth2SecurityFilter;
import com.sap.cloud.security.test.SecurityIntegrationTestRule;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.junit.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.cf.CFConstants.*;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.GRANT_TYPE;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.assertj.core.api.Assertions.assertThat;

public class HelloJavaServletIntegrationTest {

	private static Properties oldProperties;

	@ClassRule
	public static SecurityIntegrationTestRule rule = SecurityIntegrationTestRule.getInstance(XSUAA)
			.useApplicationServer()
			.addApplicationServlet(HelloJavaServlet.class, HelloJavaServlet.ENDPOINT);

	@BeforeClass
	public static void prepareTest() throws Exception {
		oldProperties = System.getProperties();
		System.setProperty(VCAP_SERVICES, IOUtils.resourceToString("/vcap.json", StandardCharsets.UTF_8));
		assertThat(Environments.getCurrent().getXsuaaConfiguration()).isNotNull();
		rule.setClientId(Environments.getCurrent().getXsuaaConfiguration().getClientId());
	}

	@After
	public void tearDown() throws Exception {
		SecurityContext.clearToken();
	}

	@AfterClass
	public static void restoreProperties() {
		System.setProperties(oldProperties);
	}

	@Test
	public void requestWithoutAuthorizationHeader_unauthenticated() throws IOException {
		HttpGet request = createGetRequest(null);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
		}
	}

	@Test
	public void requestWithEmptyAuthorizationHeader_unauthenticated() throws Exception {
		HttpGet request = createGetRequest("");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
		}
	}

	@Test
	public void request_withValidTokenWithoutScopes_unauthorized() throws IOException {
		String bearerAccessToken = rule.getPreconfiguredJwtGenerator()
				.withClaimValue(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
				.createToken()
				.getBearerAccessToken();
		HttpGet request = createGetRequest(bearerAccessToken);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_FORBIDDEN); // 403
		}
	}

	@Test
	public void request_withValidToken_ok() throws IOException {
		String  getBearerAccessToken = rule.getPreconfiguredJwtGenerator()
				.withClaimValue(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
				.withScopes(getGlobalScope("read"))
				.createToken()
				.getBearerAccessToken();
		HttpGet request = createGetRequest(getBearerAccessToken);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK); // 200
		}
	}

	private HttpGet createGetRequest(String bearerToken) {
		HttpGet httpGet = new HttpGet(rule.getApplicationServerUri() + HelloJavaServlet.ENDPOINT);
		if(bearerToken != null) {
			httpGet.setHeader(HttpHeaders.AUTHORIZATION, bearerToken);
		}
		return httpGet;
	}

	private String getGlobalScope(String scope) {
		String appId = Environments.getCurrent().getXsuaaConfiguration().getProperty(CFConstants.XSUAA.APP_ID);
		return appId + '.' + scope;
	}
}