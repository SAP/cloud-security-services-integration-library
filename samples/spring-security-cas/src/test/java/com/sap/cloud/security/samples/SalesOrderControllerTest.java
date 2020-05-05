package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.SpringADCService;
import com.sap.cloud.security.spring.context.support.WithMockOidcUser;
import org.junit.*;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SalesOrderControllerTest {

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
    @WithMockOidcUser(name="Bob.noAuthorization@test.com")
    public void readWith_Bob_403() throws Exception {
        mockMvc.perform(get("/salesOrders"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockOidcUser(name = "Alice_salesOrders@test.com")
    public void readWith_Alice_salesOrders_200() throws Exception {
        mockMvc.perform(get("/salesOrders"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockOidcUser(name = "Alice_salesOrdersBetween@test.com")
    public void readWith_Alice_italianSalesOrderWithId101_200() throws Exception {
        mockMvc.perform(get("/salesOrders/readByCountryAndId/IT/101"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockOidcUser(name = "Alice_salesOrdersBetween@test.com")
    public void readWith_Alice_italianSalesOrderWithId501_403() throws Exception {
        mockMvc.perform(get("/salesOrders/readByCountryAndId/IT/501"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockOidcUser(name ="Alice_countryCode@test.com")
    public void readWith_Alice_italianResource_200() throws Exception {
        mockMvc.perform(get("/salesOrders/readByCountry/IT"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockOidcUser(name ="Alice_countryCode@test.com")
    public void readWith_Alice_americanResource_403() throws Exception {
        mockMvc.perform(get("/salesOrders/readByCountry/US"))
                .andExpect(status().isForbidden());
    }

}


