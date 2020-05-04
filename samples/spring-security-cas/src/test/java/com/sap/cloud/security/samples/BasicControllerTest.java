package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.SpringADCService;
import com.sap.cloud.security.spring.context.support.WithMockOidcUser;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class BasicControllerTest {

    //TODO @Value("${ADC_URL:http://localhost:8181}")
    private static String adcUrl = "http://localhost:8181/";

    @Autowired
    private MockMvc mockMvc;

    @BeforeClass
    public static void adcServiceRunning() {
        try {
            boolean adcServiceRunning = new SpringADCService(new RestTemplate()).ping(URI.create(adcUrl));
            Assume.assumeTrue(adcServiceRunning);
        } catch (Exception e) {
            Assume.assumeNoException(e);
        }
    }

    @Test
    @WithMockOidcUser(username="Any@unknown.org")
    public void authenticateWithoutPermission_200() throws Exception {
        mockMvc.perform(get("/authenticate"))
                .andExpect(status().isOk());
    }

    @Test
    public void authenticateWithAnonymousUser_401() throws Exception {
        mockMvc.perform(get("/authenticate"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void healthAsAnonymous_200() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk());
    }
}


