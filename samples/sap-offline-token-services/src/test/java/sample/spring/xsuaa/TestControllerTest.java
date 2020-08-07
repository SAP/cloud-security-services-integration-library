package sample.spring.xsuaa;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.SecurityTestRule;
import com.sap.cloud.security.token.TokenClaims;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = { Application.class, TestController.class, TestSecurityConfiguration.class,
		TestServlet.class })
@AutoConfigureMockMvc
public class TestControllerTest {

	@Autowired
	private MockMvc mvc;

	@ClassRule
	public static SecurityTestRule securityTest = SecurityTestRule.getInstance(Service.XSUAA);

	@Test
	public void helloToken_noToken_notAuthenticated() throws Exception {
		mvc.perform(MockMvcRequestBuilders
				.get("/hello-token").with(bearerToken("")))
				.andDo(print())
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void helloToken_nonMatchingScope_isForbidden() throws Exception {
		String token = securityTest.getPreconfiguredJwtGenerator()
				.withLocalScopes("Read")
				.createToken()
				.getTokenValue();

		mvc.perform(MockMvcRequestBuilders
				.get("/hello-token").with(bearerToken(token)))
				.andDo(print())
				.andExpect(status().isForbidden());
	}

	@Test
	public void helloToken_matchingScope_ok() throws Exception {
		String token = securityTest.getPreconfiguredJwtGenerator()
				.withClaimValue(TokenClaims.USER_NAME, "Alice")
				.withLocalScopes("Display")
				.createToken()
				.getTokenValue();

		mvc.perform(MockMvcRequestBuilders
				.get("/hello-token").with(bearerToken(token)))
				.andDo(print())
				.andExpect(status().isOk());
	}

	@Test
	@Ignore // mockmvc cannot test WebServlets
	public void helloServlet_matchingScope_ok() throws Exception {
		//only protected by authentication, scope checks in servlet
		String token = securityTest.getPreconfiguredJwtGenerator()
				.createToken()
				.getTokenValue();

		mvc.perform(MockMvcRequestBuilders
				.get("/hello-servlet").with(bearerToken(token)))
				.andDo(print())
				.andExpect(status().isOk());

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