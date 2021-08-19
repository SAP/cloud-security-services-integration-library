package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

class DefaultOAuth2SMServiceTest {
    static DefaultOAuth2ServiceManagerService cut;
    private static String servicePlans;
    private static String serviceInstances;
    static CloseableHttpClient httpClientMock = mock(CloseableHttpClient.class);

    @BeforeAll
    static void beforeAll() throws IOException {
        servicePlans = IOUtils.resourceToString("/servicePlans.json", StandardCharsets.UTF_8);
        serviceInstances = IOUtils.resourceToString("/serviceInstances.json", StandardCharsets.UTF_8);

        OAuth2ServiceConfiguration oAuth2ServiceConfiguration = mock(OAuth2ServiceConfiguration.class);
        when(oAuth2ServiceConfiguration.getUrl()).thenReturn(URI.create("https://auth.sap.com"));
        when(oAuth2ServiceConfiguration.getProperty("sm_url")).thenReturn("https://service-manager.sap.com");
        when(oAuth2ServiceConfiguration.getClientIdentity()).thenReturn(new ClientCredentials("clientId", "clientSecret"));
        cut = new DefaultOAuth2ServiceManagerService(oAuth2ServiceConfiguration, httpClientMock);
    }

    @Test
    void getServicePlans() throws IOException {
        CloseableHttpResponse response = HttpClientTestFactory
                .createHttpResponse(servicePlans, HttpStatus.SC_OK);
        when(httpClientMock.execute(any())).thenReturn(response);
        Map<String, String> servicePlanMap = cut.getServicePlans();
        assertEquals(7, servicePlanMap.size());
    }

    @Test
    void getServiceInstances() throws IOException{
        CloseableHttpResponse response = HttpClientTestFactory
                .createHttpResponse(serviceInstances, HttpStatus.SC_OK);
        when(httpClientMock.execute(any())).thenReturn(response);
        Map<String, String> servicePlanMap = cut.getServiceInstances();
        assertEquals(4, servicePlanMap.size());
        assertNotNull(servicePlanMap.get("xsuaa-application"));
        assertEquals("037e7df6-5843-4174-9cb4-69a1f9a4da7e",servicePlanMap.get("xsuaa-application"));
        assertNotNull(servicePlanMap.get("xsuaa-broker"));
        assertEquals("bb769fcb-c8b9-4612-beac-18be9743a3b7",servicePlanMap.get("xsuaa-broker"));

    }

    @Test
    void getServiceInstancePlans() {
        Map<String, String> serviceInstanceMap = new HashMap<>();
        serviceInstanceMap.put("xsuaa-application", "037e7df6-5843-4174-9cb4-69a1f9a4da7e");
        serviceInstanceMap.put("xsuaa-broker", "bb769fcb-c8b9-4612-beac-18be9743a3b7");
        Map<String, String> servicePlanMap = new HashMap<>();
        servicePlanMap.put("bb769fcb-c8b9-4612-beac-18be9743a3b7", "broker");
        servicePlanMap.put("037e7df6-5843-4174-9cb4-69a1f9a4da7e", "application");
        servicePlanMap.put("12345678-1234-1234-abcd-123456789123", "another-plan");

        DefaultOAuth2ServiceManagerService cut = mock(DefaultOAuth2ServiceManagerService.class);

        when(cut.getServicePlans()).thenReturn(servicePlanMap);
        when(cut.getServiceInstances()).thenReturn(serviceInstanceMap);
        when(cut.getServiceInstancePlans()).thenCallRealMethod();

        Map<String, String> instancePlans = cut.getServiceInstancePlans();
        assertEquals(2, instancePlans.size());
        assertEquals("application", instancePlans.get("xsuaa-application"));
        assertEquals("broker", instancePlans.get("xsuaa-broker"));
    }
}