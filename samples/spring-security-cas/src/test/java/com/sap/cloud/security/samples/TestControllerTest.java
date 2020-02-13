package com.sap.cloud.security.samples;

import com.sap.cloud.security.spring.context.support.WithMockOidcUser;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
//@TestPropertySource(properties = {})
public class TestControllerTest {

    @Autowired
    private MockMvc mockMvc;

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
    @WithMockOidcUser(username="Alice")
    public void readWith_Alice_readAll_200() throws Exception {
        mockMvc.perform(get("/authorized"))
                .andExpect(status().isOk());
    }

}


