/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
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
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"xsuaa.uaadomain=localhost", "xsuaa.xsappname=xsapp!t0815", "xsuaa.clientid=sb-clientId!t0815" })
public class TestControllerTest {

    @Autowired
    private MockMvc mvc;

    private String jwt;

    private String jwtAdmin;

    @ClassRule
    public static SecurityTestRule rule = SecurityTestRule.getInstance(Service.XSUAA);

    @Before
    public void setUp() {
        jwt = rule.getPreconfiguredJwtGenerator()
                .withLocalScopes("Read")
                //.withClaimValue(TokenClaims.XSUAA.ORIGIN, "sap-default") // optional
                //.withClaimValue(TokenClaims.USER_NAME, "John") // optional
                .createToken().getTokenValue();
        jwtAdmin = rule.getPreconfiguredJwtGenerator()
                .withLocalScopes("Read", "Admin")
                .createToken().getTokenValue();
    }

    @Test
    public void v1_sayHello() throws Exception {
        String response = mvc
                .perform(get("/v1/sayHello").with(bearerToken(jwtAdmin)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertTrue(response.contains("sb-clientId!t0815"));
        assertTrue(response.contains("xsapp!t0815.Read"));
        assertTrue(response.contains("xsapp!t0815.Admin"));
        assertTrue(response.contains("[Read, Admin]"));
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

        assertTrue(response.contains("Read-protected method called!"));
    }

    @Test
    public void v1_accessSensitiveData_OK() throws Exception {
        String response = mvc
                .perform(get("/v1/getAdminData").with(bearerToken(jwtAdmin)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertTrue(response.contains("You got the sensitive data"));
    }

    @Test
    public void v1_accessSensitiveData_Forbidden() throws Exception {
        String jwtNoScopes = rule.getPreconfiguredJwtGenerator()
                .createToken().getTokenValue();

        mvc.perform(get("/v1/getAdminData").with(bearerToken(jwtNoScopes)))
                .andExpect(status().isForbidden());
    }

    @Test
    public void v1_accessSensitiveData_unauthenticated() throws Exception {
        mvc.perform(get("/v1/getAdminData"))
                .andExpect(status().isUnauthorized());
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
