package com.sap.cloud.security.samples;

import com.sap.cloud.security.test.ApplicationServerOptions;
import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.junit.*;

import java.io.IOException;

import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.GRANT_TYPE;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.assertj.core.api.Assertions.assertThat;

public class HelloJavaServletIntegrationTest {

	@ClassRule
	public static SecurityTestRule rule = SecurityTestRule.getInstance(XSUAA)
			.useApplicationServer()
			.addApplicationServlet(HelloJavaServlet.class, HelloJavaServlet.ENDPOINT);

	@After
	public void tearDown() {
		SecurityContext.clearToken();
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
	public void requestWithValidTokenWithoutScopes_unauthorized() throws IOException {
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
	public void requestWithValidToken_ok() throws IOException {
		String jwt = rule.getPreconfiguredJwtGenerator()
				.withClaimValue(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
				.withScopes(getGlobalScope("Read"))
				.createToken()
				.getBearerAccessToken();
		HttpGet request = createGetRequest(jwt);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
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
		return SecurityTestRule.DEFAULT_APP_ID + '.' + scope;
	}
}