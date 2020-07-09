package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.AdcService;
import com.sap.cloud.security.spring.context.support.WithMockOidcUser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // Support non-static @BeforeAll
public class BasicControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AdcService adcService;

    @BeforeAll
    public void adcServiceRunning() {
        assumeTrue(adcService.ping());
    }

    @Test
    @WithMockOidcUser("somOtherUsername")
    public void authenticateWithoutPermission_200() throws Exception {
        mockMvc.perform(get("/authenticate"))//.with(oidcLogin()))
                .andExpect(status().isOk());
    }

    @Test
    public void healthAsAnonymous_200() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk());
    }
}


