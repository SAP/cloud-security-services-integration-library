package com.sap.cloud.security.javasec.samples.usage;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static com.sap.cloud.security.javasec.samples.usage.TomcatTestServer.TOMCAT_PORT;
import static com.sap.cloud.security.javasec.samples.usage.TomcatTestServer.start;
import static org.assertj.core.api.Assertions.assertThat;

public class HelloJavaServletTest {

	private static final int TOKEN_KEY_SERVICE_PORT = 33195;

	private static PrivateKey privateKey;
	private static PublicKey publicKey;
	private static Token validToken;

	@Rule
	public WireMockRule wireMockRule = new WireMockRule(options().port(TOKEN_KEY_SERVICE_PORT));

	@BeforeClass
	public static void prepareTest() throws Exception {
		setupKeys();
		String webappDir = new File("src/test/webapp").getAbsolutePath();
		start(webappDir);
	}

	private static void setupKeys() throws Exception {
		KeyPair keys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		privateKey = keys.getPrivate();
		publicKey = keys.getPublic();
		validToken = createValidToken();
	}

	private static Token createValidToken() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		return new JwtGenerator(privateKey)
				.withAlgorithm(JwtConstants.Algorithms.RS256)
				.withHeaderParameter("jku", "http://localhost:" + TOKEN_KEY_SERVICE_PORT)
				.withClaim("cid", "sb-clientId!20")
				.createToken();
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
		HttpGet request = createGetRequest("Bearer " + validToken.getAccessToken());
		request.setHeader(HttpHeaders.AUTHORIZATION, null);
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
		}
	}

	@Test
	public void request_withValidToken() throws IOException {
		HttpGet request = createGetRequest("Bearer " + validToken.getAccessToken());
		wireMockRule.stubFor(get(urlEqualTo("/")).willReturn(aResponse().withBody(createTokenKeyResponse())));
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
		}
	}

	private String createTokenKeyResponse() throws IOException {
		return IOUtils.resourceToString("/token_keys_template.json", StandardCharsets.UTF_8)
				.replace("$kid", "default-kid")
				.replace("$public_key", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
	}

	private HttpGet createGetRequest(String bearer_token) {
		HttpGet httpPost = new HttpGet("http://localhost:" + TOMCAT_PORT + "/hello-java-security");
		httpPost.setHeader(HttpHeaders.AUTHORIZATION, bearer_token);
		return httpPost;
	}

}