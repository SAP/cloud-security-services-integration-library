package com.sap.cloud.security.javasec.test;

import org.junit.Rule;
import org.junit.Test;
import wiremock.org.apache.http.HttpStatus;
import wiremock.org.apache.http.client.methods.CloseableHttpResponse;
import wiremock.org.apache.http.client.methods.HttpGet;
import wiremock.org.apache.http.impl.client.HttpClients;

import java.io.IOException;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;

import com.sap.cloud.security.config.Service;

public class SecurityIntegrationTestRuleTest {

	public static final int PORT = 8484;
	public static final int APPLICATION_SERVER_PORT = 8383;

	@Rule
	public SecurityIntegrationTestRule rule = new SecurityIntegrationTestRule(XSUAA)
			.setPort(PORT)
			.useApplicationServer("src/test/webapp", APPLICATION_SERVER_PORT);

	public SecurityIntegrationTestRuleTest() {
		rule.getPreconfiguredJwtGenerator().withHeaderParameter("test", "abc123");
	}

	@Test
	public void getTokenKeysRequest_statusOk() throws IOException {
		HttpGet httpGet = new HttpGet("http://localhost:" + PORT + "/token_keys");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(httpGet)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
			// TODO 22.11.19 c5295400: test content
		}
	}
}
