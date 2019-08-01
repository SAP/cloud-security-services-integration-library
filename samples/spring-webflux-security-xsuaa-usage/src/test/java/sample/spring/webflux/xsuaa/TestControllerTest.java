package sample.spring.webflux.xsuaa;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.sap.cloud.security.xsuaa.test.JwtGenerator;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureWebTestClient
public class TestControllerTest {

	@Autowired
	private WebTestClient webClient;

	@Test
	public void unauthorizedRequest() {
		JwtGenerator jwtGenerator = new JwtGenerator();

		webClient.method(HttpMethod.GET).uri("/v1/sayHello").contentType(MediaType.APPLICATION_JSON_UTF8)
				.header(HttpHeaders.AUTHORIZATION, jwtGenerator.getTokenForAuthorizationHeader()).exchange()
				.expectStatus().isUnauthorized();
	}

}
