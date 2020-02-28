package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.SpringADCService;
import com.sap.cloud.security.spring.context.support.WithMockOidcUser;
import org.junit.*;
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
public class TestControllerTest {

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
    @WithMockOidcUser(username="Any")
    public void readWithoutPermission_403() throws Exception {
        mockMvc.perform(get("/authorized"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockOidcUser(username="Bob")
    public void readWith_Bob_403() throws Exception {
        mockMvc.perform(get("/authorized"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockOidcUser(username="Alice_salesOrdersRes")
    public void readWith_Alice_readAll_200() throws Exception {
        mockMvc.perform(get("/authorized"))
                .andExpect(status().isOk());
    }

}


