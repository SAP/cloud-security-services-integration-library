package com.sap.cloud.security.samples;

import com.sap.cloud.security.cas.client.AdcServiceDefault;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.net.URI;

import static com.sap.cloud.security.spring.context.support.MockOidcTokenRequestPostProcessor.userToken;
import static com.sap.cloud.security.spring.context.support.MockOidcTokenRequestPostProcessor.userTokenWithAuthorities;
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
        assumeTrue(new AdcServiceDefault(URI.create(adcUrl)).ping());
    }

    @Test
    public void readWith_Bob_403() throws Exception {
        mockMvc.perform(get("/salesOrders")
                .with(userToken("Bob.noAuthorization@test.com")))
                .andExpect(status().isForbidden());
    }

    @Test
    //@WithMockOidcUser(name = "Alice_salesOrders@test.com", authorities = {"read:salesOrders"})
    public void readWith_Alice_salesOrders_200() throws Exception {
        mockMvc.perform(get("/salesOrders")
                .with(userTokenWithAuthorities("Alice_salesOrders@test.com", "read:salesOrders")))
                .andExpect(status().isOk());
    }

    @Test
    //@WithMockOidcUser(name = "Alice_salesOrdersBetween@test.com")
    public void readWith_Alice_italianSalesOrderWithId101_200() throws Exception {
        mockMvc.perform(get("/salesOrders/readByCountryAndId/IT/101")
                .with(userToken("Alice_salesOrdersBetween@test.com")))
                .andExpect(status().isOk());
    }

    @Test
    //@WithMockOidcUser(name = "Alice_salesOrdersBetween@test.com")
    public void readWith_Alice_italianSalesOrderWithId501_403() throws Exception {
        mockMvc.perform(get("/salesOrders/readByCountryAndId/IT/501")
                .with(userToken("Alice_salesOrdersBetween@test.com")))
                .andExpect(status().isForbidden());
    }

    @Test
    //@WithMockOidcUser(name ="Alice_countryCode@test.com")
    public void readWith_Alice_italianResource_200() throws Exception {
        mockMvc.perform(get("/salesOrders/readByCountry/IT")
                .with(userToken("Alice_countryCode@test.com")))
                .andExpect(status().isOk());
    }

    @Test
    //@WithMockOidcUser(name ="Alice_countryCode@test.com")
    public void readWith_Alice_americanResource_403() throws Exception {
        mockMvc.perform(get("/salesOrders/readByCountry/US")
                .with(userToken("Alice_countryCode@test.com")))
                .andExpect(status().isForbidden());
    }

}


