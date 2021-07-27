package com.sap.cloud.security.xsuaa;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Properties;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class K8SServiceConfigurationAccessorTest {

    static K8SServiceConfigurationAccessor cut;

    @BeforeAll
    static void beforeAll() {
        File file = new File("src/test/resources");
        String absolutePath = file.getAbsolutePath();
        cut = new K8SServiceConfigurationAccessor(absolutePath + "/k8s/xsuaa");
    }

    @Test
    void getXsuaaServiceProperties() {
        Properties properties = cut.getXsuaaServiceProperties();
        assertEquals("myClientId", properties.getProperty(CLIENT_ID));
        assertEquals("mySecret", properties.getProperty(CLIENT_SECRET));
        assertEquals("https://auth.sap.com",properties.getProperty(URL));
        assertEquals("myAppName", properties.getProperty(XSUAA.APP_ID));
        assertEquals(4 , properties.size());
    }

    @Test
    void getIasServiceProperties() {
        assertThrows(UnsupportedOperationException.class, cut::getIasServiceProperties, "IAS is not supported");
    }
}