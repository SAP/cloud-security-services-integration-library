package sample.spring.xsuaa.junitjupiter;

import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.extension.IasExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.io.IOException;

import static com.sap.cloud.security.test.SecurityTest.*;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
		"identity.clientid=" + DEFAULT_CLIENT_ID }) // TODO
@ExtendWith(IasExtension.class)
public class TestControllerIasTest {

	@Autowired
	private MockMvc mvc;

	private String jwt;

	@BeforeEach
	public void setup(SecurityTestContext securityTest) throws IOException {
		jwt = securityTest.getPreconfiguredJwtGenerator()
				.withClaimsFromFile("/iasClaims.json")
				.createToken().getTokenValue();
	}

	@Test
	public void v1_sayHello() throws Exception {
		String response = mvc.perform(get("/v1/sayHello").with(bearerToken(jwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("sb-clientId!t0815"));
		assertTrue(response.contains("xsapp!t0815.Read"));
		assertTrue(response.contains("[Read]"));
	}

	@Test
	public void v2_sayHello() throws Exception {
		String response = mvc
				.perform(get("/v2/sayHello").with(bearerToken(jwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("Hello Jwt-Protected World!"));
	}

	@Test
	public void v1_readData_OK() throws Exception {
		String response = mvc
				.perform(get("/v1/method").with(bearerToken(jwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("You got the sensitive data for zone 'the-zone-id'."));
	}

	@Test
	public void v1_readData_FORBIDDEN(SecurityTestContext securityTest) throws Exception {
		String jwtNoScopes = securityTest.getPreconfiguredJwtGenerator()
				.createToken().getTokenValue();

		mvc.perform(get("/v1/method").with(bearerToken(jwtNoScopes)))
				.andExpect(status().isForbidden());
	}

	private static class BearerTokenRequestPostProcessor implements RequestPostProcessor {
		private String token;

		public BearerTokenRequestPostProcessor(String token) {
			this.token = token;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + this.token);
			return request;
		}
	}

	private static BearerTokenRequestPostProcessor bearerToken(String token) {
		return new BearerTokenRequestPostProcessor(token);
	}
}

