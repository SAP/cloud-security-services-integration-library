package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.*;

import static org.assertj.core.api.Assertions.assertThat;

public class HelloJavaServletTestWithoutWiremock {

	private static PrivateKey privateKey;
	private static Token validToken;
	public static final int TOMCAT_PORT = 8282;
	private static TomcatTestServer tomcatTestServer;

	@BeforeClass
	public static void prepareTest() throws Exception {
		String webappDir = new File("src/test/webapp_customTokenKeyService").getAbsolutePath();
		tomcatTestServer = new TomcatTestServer(webappDir, TOMCAT_PORT);
		tomcatTestServer.start();
		privateKey = new TestOAuthTokenKeyService().getPrivateKey();
		validToken = createValidToken();
	}

	@AfterClass
	public static void tearDown() {
		tomcatTestServer.stop();
	}

	@Test
	public void request_withValidToken() throws IOException {
		HttpGet request = createGetRequest("Bearer " + validToken.getAccessToken());
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
		}
	}

	private static Token createValidToken() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		return new JwtGenerator(privateKey)
				.withAlgorithm(JwtConstants.Algorithms.RS256)
				.withHeaderParameter("jku", "http://localhost:1234") // not actually called
				.withClaim("cid", "sb-clientId!20")
				.createToken();
	}

	private HttpGet createGetRequest(String bearer_token) {
		HttpGet httpPost = new HttpGet("http://localhost:" + TOMCAT_PORT + "/hello-java-security");
		httpPost.setHeader(HttpHeaders.AUTHORIZATION, bearer_token);
		return httpPost;
	}

}