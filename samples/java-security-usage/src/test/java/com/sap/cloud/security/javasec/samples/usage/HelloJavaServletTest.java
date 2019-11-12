package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

//@TestServletSecurity
public class HelloJavaServletTest {

	public static final int PORT = 8281;
	private static final Logger logger = LoggerFactory.getLogger(HelloJavaServletTest.class);
	private static Tomcat tomcat;
	private static CountDownLatch lock = new CountDownLatch(1);

	@BeforeClass
	public static void setUpTomcat() {
		Executors.newFixedThreadPool(1).submit(() -> {
			tomcat = new Tomcat();
			tomcat.setPort(PORT);
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
		HttpGet request = createGetRequest("Bearer token");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
		}

	}

	@Test
	public void requestWithoutHeader_statusUnauthorized() throws IOException {
		HttpGet request = createGetRequest("Bearer token");
		request.setHeader(HttpHeaders.AUTHORIZATION, null);

		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
		}

	}

	@Test
	public void request_withValidToken() throws IOException {
		HttpGet request = createGetRequest("Bearer valid token");

		try (CloseableHttpResponse response = HttpClients.createDefault().execute(request)) {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
		}

	}

	private HttpGet createGetRequest(String bearer_token) {
		HttpGet httpPost = new HttpGet("http://localhost:" + PORT + "/hello-java-security");
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