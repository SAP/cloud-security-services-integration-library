package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySet;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;
import com.sap.cloud.security.xsuaa.jwt.JwtSignatureAlgorithm;

import org.apache.commons.io.IOUtils;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import wiremock.org.apache.http.HttpStatus;
import wiremock.org.apache.http.client.methods.CloseableHttpResponse;
import wiremock.org.apache.http.client.methods.HttpGet;
import wiremock.org.apache.http.impl.client.HttpClients;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
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

	@Test
	public void getTokenKeysRequest_responseContainsExpectedTokenKeys() throws IOException {
		HttpGet httpGet = new HttpGet("http://localhost:" + PORT + "/token_keys");

		try (CloseableHttpResponse response = HttpClients.createDefault().execute(httpGet)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
			JsonWebKeySet keySet = JsonWebKeySetFactory.createFromJson(readContent(response));
			assertThat(keySet.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "default-kid")).isNotNull();
		}
	}

	@Test
	public void generatesTokenWithClientId() {
		Token generatedToken = rule.setClientId("customClientId").createToken();
		assertThat(generatedToken.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID))
				.isEqualTo("customClientId");
	}

	@Test
	public void generatesTokenWithOtherClaimsAndHeaderParameter() {
		Token generatedToken = rule.setClientId("customClientId").getPreconfiguredJwtGenerator()
				.withClaimValue(TokenClaims.ISSUER, "issuer")
				.withScopes("appid.scope1")
				.withHeaderParameter(TokenHeader.TYPE, "type").createToken();

		assertThat(generatedToken.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo("customClientId");
		assertThat(generatedToken.getClaimAsStringList(TokenClaims.XSUAA.SCOPES).size()).isEqualTo(1);
		assertThat(generatedToken.getClaimAsString(TokenClaims.ISSUER)).isEqualTo("issuer");
		assertThat(generatedToken.getHeaderParameterAsString(TokenHeader.TYPE)).isEqualTo("type");
	}

	@Test
	public void testRuleIsInitializedCorrectly() {
		assertThat(rule.getAppServerUri()).isEqualTo("http://localhost:" + APPLICATION_SERVER_PORT);
		assertThat(rule.getWireMockRule()).isNotNull();
		assertThat(rule.createToken().getAccessToken())
				.isEqualTo(rule.getPreconfiguredJwtGenerator().createToken().getAccessToken());
	}

	private String readContent(CloseableHttpResponse response) throws IOException {
		return IOUtils.readLines(response.getEntity().getContent(), StandardCharsets.UTF_8).stream()
				.collect(Collectors.joining());
	}

	public static class SecurityIntegrationTestRuleTestWithoutApplicationServer {

		@Rule
		public SecurityIntegrationTestRule rule = SecurityIntegrationTestRule.getInstance(XSUAA);

		@Test
		public void testRuleIsInitializedCorrectly() {
			assertThat(rule.getAppServerUri()).isNull();
			assertThat(rule.getWireMockRule()).isNotNull();
		}
	}

	public static class SecurityIntegrationApplicationServerFaults {

		@Test
		public void onlyXsuaaIsSupportedYet() {
			SecurityIntegrationTestRule cut = SecurityIntegrationTestRule.getInstance(Service.IAS);

			assertThatThrownBy(() -> cut.before())
					.isInstanceOf(UnsupportedOperationException.class)
					.hasMessageContaining(String.format("Service %s is not yet supported", Service.IAS));
		}

	}
}
