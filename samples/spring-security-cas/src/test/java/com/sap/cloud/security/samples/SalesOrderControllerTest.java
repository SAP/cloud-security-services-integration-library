package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.DefaultAdcService;
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
public class SalesOrderControllerTest {

    //TODO @Value("${ADC_URL:http://localhost:8181}")
    private static String adcUrl = "http://localhost:8181/";

    @Autowired
    private MockMvc mockMvc;

    @BeforeAll
    public static void adcServiceRunning() {
        assumeTrue(new DefaultAdcService(URI.create(adcUrl)).ping());
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


