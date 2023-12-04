/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.security;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.test.SecurityTestRule;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static sample.spring.security.util.MockBearerTokenRequestPostProcessor.bearerToken;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
// Test properties are provided with /resources/application.yml
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
    public void setUp() {
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

        assertTrue(response.contains(SecurityTestRule.DEFAULT_CLIENT_ID));
        assertTrue(response.contains(JwtGenerator.DEFAULT_APP_TID));
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
        assertTrue(response.contains("You got the sensitive data for zone 'the-app-tid'."));
    }

    @Test
    public void readData_FORBIDDEN() throws Exception {
        String jwtNoScopes = ruleXsuaa.getPreconfiguredJwtGenerator()
                .createToken().getTokenValue();

        mvc.perform(get("/method").with(bearerToken(jwtNoScopes)))
                .andExpect(status().isForbidden());
    }

}
