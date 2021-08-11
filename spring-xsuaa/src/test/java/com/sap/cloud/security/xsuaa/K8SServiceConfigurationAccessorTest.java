package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2SMService;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class K8SServiceConfigurationAccessorTest {
    private static final String SERVICE_PLANS = "/v1/service_plans";
    private static final String SERVICE_INSTANCES = "/v1/service_instances";
    static K8SServiceConfigurationAccessor cut;

    @BeforeAll
    static void beforeAll() throws IOException {
        File file = new File("src/test/resources");
        String absolutePath = file.getAbsolutePath();
        String serviceInstances = IOUtils.resourceToString("/k8s/serviceInstances.json", StandardCharsets.UTF_8);
        String servicePlans = IOUtils.resourceToString("/k8s/servicePlans.json", StandardCharsets.UTF_8);

        XsuaaOAuth2SMService smServiceMock = mock(XsuaaOAuth2SMService.class);
        when(smServiceMock.executeRequest(SERVICE_PLANS)).thenReturn(createResponseEntity(servicePlans));
        when(smServiceMock.executeRequest(SERVICE_INSTANCES)).thenReturn(createResponseEntity(serviceInstances));
        when(smServiceMock.getServiceInstances()).thenCallRealMethod();
        when(smServiceMock.getServicePlans()).thenCallRealMethod();
        when(smServiceMock.getServiceInstancePlans()).thenCallRealMethod();

        cut = new K8SServiceConfigurationAccessor(absolutePath + "/k8s/xsuaa", absolutePath + "/k8s/service-manager", null);
        cut.setSmService(smServiceMock);
    }

    @Test
    void getXsuaaServiceProperties() {
        Properties properties = cut.getXsuaaServiceConfiguration();
        assertEquals("myClientId", properties.getProperty(CLIENT_ID));
        assertEquals("mySecret", properties.getProperty(CLIENT_SECRET));
        assertEquals("https://auth.sap.com",properties.getProperty(URL));
        assertEquals("myAppName", properties.getProperty(XSUAA.APP_ID));
        assertEquals(4 , properties.size());
    }

    @Test
    void getIasServiceProperties() {
        assertThrows(UnsupportedOperationException.class, cut::getIasServiceConfiguration, "IAS is not supported");
    }

    private static ResponseEntity<String> createResponseEntity(String responseBody) {
        HttpHeaders header = new HttpHeaders();
        header.setContentType(MediaType.APPLICATION_JSON);
        return new ResponseEntity<>(
                responseBody,
                header,
                HttpStatus.OK
        );
    }
}