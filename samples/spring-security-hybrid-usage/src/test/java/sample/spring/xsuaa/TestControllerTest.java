package sample.spring.xsuaa;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.SecurityTestRule;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.io.IOException;

import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
//@TestPropertySource(properties = {"xsuaa.uaadomain=localhost", "xsuaa.xsappname=xsapp!t0815", "xsuaa.clientid=sb-clientId!t0815" })
public class TestControllerTest {

    @Autowired
    private MockMvc mvc;

    private String jwtXsuaa;
    private String jwtIas;

    @ClassRule
    public static SecurityTestRule ruleXsuaa = SecurityTestRule.getInstance(Service.XSUAA);
    @ClassRule
    public static SecurityTestRule ruleIas = SecurityTestRule.getInstance(Service.IAS);

    @Before
    public void setUp() throws IOException {
        jwtXsuaa = ruleXsuaa.getPreconfiguredJwtGenerator()
                .withLocalScopes("Read")
                .createToken().getTokenValue();
        jwtIas = ruleIas.getPreconfiguredJwtGenerator()
                .withClaimsFromFile("/iasClaims.json")
                .createToken().getTokenValue();
    }

    @Test
    public void sayHello() throws Exception {
        String response = mvc
                .perform(get("/sayHello").with(bearerToken(jwtXsuaa)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertTrue(response.contains("sb-clientId!t0815"));
        assertTrue(response.contains("xsapp!t0815.Read"));

        response = mvc
                .perform(get("/sayHello").with(bearerToken(jwtIas)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertTrue(response.contains("sb-clientId!t0815"));
        assertTrue(response.contains("the-zone-id"));
    }

    @Test
    public void readData_OK() throws Exception {
        String response = mvc
                .perform(get("/method").with(bearerToken(jwtXsuaa)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertTrue(response.contains("You got the sensitive data for zone 'the-zone-id'."));

        response = mvc
                .perform(get("/method").with(bearerToken(jwtIas)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertTrue(response.contains("You got the sensitive data for zone 'the-zone-id'."));
    }

    @Test
    public void readData_FORBIDDEN() throws Exception {
        String jwtNoScopes = ruleXsuaa.getPreconfiguredJwtGenerator()
                .createToken().getTokenValue();

        mvc.perform(get("/method").with(bearerToken(jwtNoScopes)))
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

    private static RequestPostProcessor bearerToken(String token) {
        return new BearerTokenRequestPostProcessor(token);
    }

}
