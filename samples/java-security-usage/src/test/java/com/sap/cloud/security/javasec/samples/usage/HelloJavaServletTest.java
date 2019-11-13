package com.sap.cloud.security.javasec.samples.usage;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

//@TestServletSecurity
public class HelloJavaServletTest {

	public static final int TOMCAT_PORT = 8281;
	public static final int TOKEN_KEY_SERVICE_PORT = 33195;

	private static final Logger logger = LoggerFactory.getLogger(HelloJavaServletTest.class);
	private static Tomcat tomcat;
	private static CountDownLatch lock = new CountDownLatch(1);
	@Rule
	public WireMockRule wireMockRule = new WireMockRule(options().port(33195));
	private String validToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzMxOTUvbXktc3ViYWNjb3VudC1zdWJkb21haW4vdG9rZW5fa2V5cyIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkifQ.eyJleHRfYXR0ciI6eyJ6ZG4iOiJteS1zdWJhY2NvdW50LXN1YmRvbWFpbiJ9LCJ6aWQiOiJteS1zdWJhY2NvdW50LXN1YmRvbWFpbi1pZCIsInpkbiI6Im15LXN1YmFjY291bnQtc3ViZG9tYWluIiwiZ3JhbnRfdHlwZSI6InVybjppZXRmOnBhcmFtczpvYXV0aDpncmFudC10eXBlOnNhbWwyLWJlYXJlciIsInVzZXJfbmFtZSI6InRlc3R1c2VyIiwib3JpZ2luIjoidXNlcklkcCIsImV4cCI6Njk3NDAzMTYwMCwiaWF0IjoxNTczNjQyMTM1LCJlbWFpbCI6InRlc3R1c2VyQHRlc3Qub3JnIiwiY2lkIjoic2ItY2xpZW50SWQhMjAifQ.apajzC8DTdJ1TyJWBwi-TqlBB-03d9Z39etVzDLzmsBBoXeB2mBEjvL6JukSXpT1h8-D3CUOrbdORrDzsWEXkHOEFgGT7Yv-ZbZQ_5DoDW4BzdVvQpvsXxaJOw00R09ecGT5gu734Xbgu9SczU9HNC4lWG-FVDAm9HLqXMHV-dy0a6vPetkTGfsKk4bswBR_Cix1_chQB3rkw-j7_SfO7qX0eDNL5e0xThcVUkIoV9c3IGGPqpA9GtwHeRM1_JK4mAcKiUxb2M_TQZKiaQC-grAAdjVabqt-2nofvRG7TXrwE7dfuUBLEOIGG2W9zC0yrNZtKZqYo3byPz9WyQe0PA";

	@BeforeClass
	public static void setUpTomcat() throws IOException {
		Executors.newFixedThreadPool(1).submit(() -> {
			tomcat = new Tomcat();
			tomcat.setPort(TOMCAT_PORT);
			try {
				String webappDir = new File("src/test/webapp").getAbsolutePath();
				tomcat.addWebapp("", webappDir);
				tomcat.start();
			} catch (LifecycleException | ServletException e) {
				logger.error("Failed to start tomcat", e);
			}
			lock.countDown();
			tomcat.getServer().await();
		});
	}

	@Before
	public void setUp() throws InterruptedException {
		lock.await();
	}

	@Test
	public void requestWithoutToken_statusUnauthorized() throws IOException {
		HttpGet request = createGetRequest("Bearer ");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
		}

	}

	@Test
	public void requestWithoutHeader_statusUnauthorized() throws IOException {
		HttpGet request = createGetRequest("Bearer " + validToken);
		request.setHeader(HttpHeaders.AUTHORIZATION, null);

		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
		}

	}

	@Test
	public void request_withValidToken() throws IOException {
		HttpGet request = createGetRequest("Bearer " + validToken);
		wireMockRule.stubFor(get(urlEqualTo("/token_keys"))
				.willReturn(aResponse().withBody(loadTokenAsString())));

		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
		}
	}

	protected String loadTokenAsString() throws IOException {
		String publicKey = readFromFile("/publicKey.txt");
		return readFromFile("/token_keys_template.json")
				.replace("$kid", "keyId")
				.replace("$public_key", publicKey);
	}

	protected String readFromFile(String path) throws IOException {
		return IOUtils.resourceToString(path, StandardCharsets.UTF_8);
	}

	private HttpGet createGetRequest(String bearer_token) {
		HttpGet httpPost = new HttpGet("http://localhost:" + TOMCAT_PORT + "/hello-java-security");
		httpPost.setHeader(HttpHeaders.AUTHORIZATION, bearer_token);
		return httpPost;
	}

	public void doGetIT() {
		//similar to WEB MVC Test that executes the Servlet Filter chain
		//MockTokenKeyService.getPublicKey -->
		//TokenKeyServiceWithCache.getPubliKey -> PublicKey which fits to the private key, the dummyToken was signed with

		// How to inject to ServletFilter
	}
}