package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.DefaultADCService;
import com.sap.cloud.security.spring.context.support.WithMockOidcUser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.net.URI;

import static org.junit.jupiter.api.Assumptions.assumeTrue;
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
        assumeTrue(new DefaultADCService().ping(URI.create(adcUrl)));
    }

    @Test
    @WithMockOidcUser(name = "Any@unknown.org" )
    public void authenticateWithoutPermission_200() throws Exception {
        mockMvc.perform(get("/authenticate"))
                .andExpect(status().isOk());
    }

    @Test
    public void healthAsAnonymous_200() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk());
    }
}


