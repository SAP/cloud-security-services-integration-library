package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeyConstants;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import wiremock.org.apache.http.HttpStatus;
import wiremock.org.apache.http.client.methods.CloseableHttpResponse;
import wiremock.org.apache.http.client.methods.HttpGet;
import wiremock.org.apache.http.impl.client.HttpClients;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SecurityIntegrationTestRuleTest {

	private static final int PORT = 8484;
	private static final int APPLICATION_SERVER_PORT = 8383;

	private static final RSAKeys RSA_KEYS = RSAKeys.generate();

	@ClassRule
	public static SecurityIntegrationTestRule rule = SecurityIntegrationTestRule.getInstance(XSUAA)
			.setPort(PORT)
			.setKeys(RSA_KEYS)
			.useApplicationServer("src/test/webapp", APPLICATION_SERVER_PORT);

	public SecurityIntegrationTestRuleTest() {
		rule.getPreconfiguredJwtGenerator().withHeaderParameter("test", "abc123");
	}

	@Test
	public void getTokenKeysRequest_responseContainsExpectedTokenKeys() throws IOException {
		HttpGet httpGet = new HttpGet("http://localhost:" + PORT + "/token_keys");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(httpGet)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
			String content = readContent(response);
			JSONArray tokenKeys = new JSONObject(content).getJSONArray(JsonWebKeyConstants.KEYS_PARAMETER_NAME);
			assertThat(tokenKeys).hasSize(1);
			assertThat(tokenKeys.get(0)).isInstanceOf(JSONObject.class);
			JSONObject tokenKeyObject = (JSONObject) tokenKeys.get(0);
			String encodedPublicKey = Base64.getEncoder().withoutPadding()
					.encodeToString(RSA_KEYS.getPublic().getEncoded());
			assertThat(tokenKeyObject.get(JsonWebKeyConstants.VALUE_PARAMETER_NAME)).isEqualTo(encodedPublicKey);
		}
	}

	@Test
	public void testRuleIsInitializedCorrectly() {
		assertThat(rule.getAppServerUri()).isEqualTo("http://localhost:" + APPLICATION_SERVER_PORT);
		assertThat(rule.getWireMockRule()).isNotNull();
		assertThat(rule.createToken().getAccessToken()).isEqualTo(rule.getPreconfiguredJwtGenerator().createToken().getAccessToken());
	}

	private String readContent(CloseableHttpResponse response) throws IOException {
		return IOUtils.readLines(response.getEntity().getContent(), StandardCharsets.UTF_8).stream()
				.collect(Collectors.joining());
	}

	public static class SecurityIntegrationTestRuleTestWithouthApplicationServer {

		@Rule
		public SecurityIntegrationTestRule rule = SecurityIntegrationTestRule.getInstance(XSUAA);

		@Test
		public void testRuleIsInitializedCorrectly() {
			assertThat(rule.getAppServerUri()).isNull();
			assertThat(rule.getWireMockRule()).isNotNull();
		}
	}

	public static class SecurityIntegrationTestRuleTestApplicationServerFaults {

		@Test
		public void onlyXsuaaIsSupportedYet() {
			SecurityIntegrationTestRule cut = SecurityIntegrationTestRule.getInstance(Service.IAS);

			assertThatThrownBy(() -> cut.before())
					.isInstanceOf(IllegalStateException.class)
					.hasMessageContaining(String.format("Service %s is not yet supported", Service.IAS));
		}
	}
}
