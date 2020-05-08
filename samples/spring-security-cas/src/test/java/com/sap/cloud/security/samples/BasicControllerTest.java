package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.DefaultAdcService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.net.URI;

import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class BasicControllerTest {

    //TODO @Value("${ADC_URL:http://localhost:8181}")
    private static String adcUrl = "http://localhost:8181/";

    @Autowired
    private MockMvc mockMvc;

    @BeforeAll
    public static void adcServiceRunning() {
        assumeTrue(new DefaultAdcService(URI.create(adcUrl)).ping());
    }

    @Test
    public void authenticateWithoutPermission_200() throws Exception {
        mockMvc.perform(get("/authenticate").with(oidcLogin()))
                .andExpect(status().isOk());
    }

    @Test
    public void healthAsAnonymous_200() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk());
    }
}


