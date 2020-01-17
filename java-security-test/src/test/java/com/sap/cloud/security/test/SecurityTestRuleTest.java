package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySet;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;
import com.sap.cloud.security.xsuaa.jwt.JwtSignatureAlgorithm;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.test.ApplicationServerOptions.forService;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;

public class SecurityTestRuleTest {

	private static final int PORT = 8484;
	private static final int APPLICATION_SERVER_PORT = 8383;
	private static final String UTF_8 = StandardCharsets.UTF_8.displayName();
	private static final String PUBLIC_KEY_PATH = "src/main/resources/publicKey.txt";
	private static final String PRIVATE_KEY_PATH = "src/main/resources/privateKey.txt";

	@ClassRule
	public static SecurityTestRule cut = SecurityTestRule.getInstance(XSUAA)
			.setPort(PORT)
			.setKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH)
			.useApplicationServer(forService(XSUAA).usePort(APPLICATION_SERVER_PORT))
			.addApplicationServlet(TestServlet.class, "/hi");

	@Test
	public void getTokenKeysRequest_responseContainsExpectedTokenKeys()
			throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

		HttpGet httpGet = new HttpGet("http://localhost:" + PORT + "/token_keys");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(httpGet)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
			JsonWebKeySet keySet = JsonWebKeySetFactory.createFromJson(readContent(response));
			PublicKey actualPublicKey = keySet
					.getKeyByAlgorithmAndId(JwtSignatureAlgorithm.RS256, "default-kid").getPublicKey();

			assertThat(actualPublicKey).isEqualTo(RSAKeys.loadPublicKey(PUBLIC_KEY_PATH));
		}
	}

	@Test
	public void generatesTokenWithOtherClaimsAndHeaderParameter() {
		Token generatedToken = cut.getPreconfiguredJwtGenerator()
				.withClaimValue(TokenClaims.ISSUER, "issuer")
				.withScopes(SecurityTestRule.DEFAULT_APP_ID + ".scope1")
				.withHeaderParameter(TokenHeader.TYPE, "type").createToken();

		assertThat(generatedToken.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID))
				.isEqualTo(SecurityTestRule.DEFAULT_CLIENT_ID);
		assertThat(generatedToken.getClaimAsStringList(TokenClaims.XSUAA.SCOPES).size()).isEqualTo(1);
		assertThat(generatedToken.getClaimAsString(TokenClaims.ISSUER)).isEqualTo("issuer");
		assertThat(generatedToken.getHeaderParameterAsString(TokenHeader.TYPE)).isEqualTo("type");
	}

	@Test
	public void testRuleIsInitializedCorrectly() {
		assertThat(cut.getApplicationServerUri()).isEqualTo("http://localhost:" + APPLICATION_SERVER_PORT);
		assertThat(cut.getWireMockRule()).isNotNull();
		assertThat(cut.createToken().getAccessToken())
				.isEqualTo(cut.getPreconfiguredJwtGenerator().createToken().getAccessToken());
	}

	@Test
	public void servletFilterServesTestServlet() throws IOException {
		HttpGet httpGet = new HttpGet(cut.getApplicationServerUri() + "/hi");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(httpGet)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
		}
	}

	@Test
	public void setKeys_invalidPath_throwsException()
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		assertThatThrownBy(() -> SecurityTestRule.getInstance(XSUAA)
				.setKeys("doesNotExist", "doesNotExist"))
						.isInstanceOf(RuntimeException.class);
	}

	public static class SecurityTestRuleWithMockServlet {

		private HttpServlet mockServlet = Mockito.mock(HttpServlet.class);

		@Rule
		public SecurityTestRule mockServletRule = SecurityTestRule.getInstance(XSUAA)
				.useApplicationServer()
				.addApplicationServlet(new ServletHolder(mockServlet), "/");

		@Test
		public void testThatServletMethodIsNotCalled() throws ServletException, IOException {
			HttpGet httpGet = new HttpGet(mockServletRule.getApplicationServerUri());
			try (CloseableHttpResponse response = HttpClients.createDefault().execute(httpGet)) {
				assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
			}
			Mockito.verify(mockServlet, Mockito.times(0)).service(any(), any());
		}

	}

	public static class SecurityTestRuleWithoutApplicationServer {

		@Rule
		public SecurityTestRule rule = SecurityTestRule.getInstance(XSUAA);

		@Test
		public void testRuleIsInitializedCorrectly() {
			assertThat(rule.getApplicationServerUri()).isNull();
			assertThat(rule.getWireMockRule()).isNotNull();
		}
	}

	// TODO IAS
	public static class SecurityTestRuleApplicationServerFaults {

		@Test
		public void onlyXsuaaIsSupportedYet() {
			assertThatThrownBy(() -> SecurityTestRule.getInstance(Service.IAS))
					.isInstanceOf(UnsupportedOperationException.class)
					.hasMessageContaining(String.format("Identity Service %s is not yet supported", Service.IAS));
		}

	}

	public static class TestServlet extends HttpServlet {
		@Override
		protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
			response.setStatus(HttpServletResponse.SC_OK);
			response.setContentType("text/plain");
			response.setCharacterEncoding(UTF_8);
			response.getWriter().print("Hi!");
		}
	}

	private static String readContent(CloseableHttpResponse response) throws IOException {
		return IOUtils.readLines(response.getEntity().getContent(), UTF_8).stream()
				.collect(Collectors.joining());
	}

}
