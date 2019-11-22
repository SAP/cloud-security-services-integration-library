package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.javasec.test.SecurityIntegrationTestRule;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

public class HelloJavaServletTest {

	private static final String EMAIL_ADDRESS = "test.email@example.org";
	public static final int APPLICATION_SERVER_PORT = 8282;
	private static Properties oldProperties;

	@Rule
	public SecurityIntegrationTestRule rule = new SecurityIntegrationTestRule()
			.setPort(8181)
			.useApplicationServer("src/test/webapp", APPLICATION_SERVER_PORT);

	@BeforeClass
	public static void prepareTest() throws Exception {
		oldProperties = System.getProperties();
		System.setProperty("VCAP_SERVICES", IOUtils.resourceToString("/vcap.json", StandardCharsets.UTF_8));
	}

	@AfterClass
	public static void restoreProperties() {
		System.setProperties(oldProperties);
	}

	@Test
	public void requestWithoutToken_statusUnauthorized() throws IOException {
		HttpGet request = createGetRequest("Bearer ");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
		}
	}

	@Test
	public void requestWithoutHeader_statusUnauthorized() throws Exception {
		Token token = rule.getToken();

		HttpGet request = createGetRequest("Bearer " + token.getAccessToken());
		request.setHeader(HttpHeaders.AUTHORIZATION, null);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
		}
	}

	@Test
	public void request_withValidToken() throws IOException {
		rule.getPreconfiguredJwtGenerator().withClaim(TokenClaims.XSUAA.EMAIL, EMAIL_ADDRESS);
		HttpGet request = createGetRequest("Bearer " + rule.getToken().getAccessToken());

		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			String responseBody = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
			assertThat(responseBody).contains(EMAIL_ADDRESS);
		}
	}

	private HttpGet createGetRequest(String bearer_token) {
		HttpGet httpGet = new HttpGet("http://localhost:" + APPLICATION_SERVER_PORT + "/hello-java-security");
		httpGet.setHeader(HttpHeaders.AUTHORIZATION, bearer_token);
		return httpGet;
	}

}