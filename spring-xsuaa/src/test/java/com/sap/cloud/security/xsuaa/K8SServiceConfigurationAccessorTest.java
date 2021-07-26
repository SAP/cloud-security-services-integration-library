package com.sap.cloud.security.xsuaa;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Properties;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

class K8SServiceConfigurationAccessorTest {
    final static String DEFAULT_XSUAA_PATH = "/etc/secrets/sapcp/xsuaa";
    final static K8SServiceConfigurationAccessor cut = Mockito.mock(K8SServiceConfigurationAccessor.class);

    @BeforeAll
    static void beforeAll() throws IOException {
        File xsuaaInstance1 = mockFile("xsuaa-1", DEFAULT_XSUAA_PATH + "/xsuaa1");
        File xsuaaInstance2 = mockFile("xsuaa-2", DEFAULT_XSUAA_PATH + "/xsuaa2");

        final File clientId = mockFile(CLIENT_ID, DEFAULT_XSUAA_PATH + "/clientid");
        final File clientSecret = mockFile(CLIENT_SECRET, DEFAULT_XSUAA_PATH + "/clientsecret");
        final File url = mockFile(URL, DEFAULT_XSUAA_PATH + "/url");
        final File appId = mockFile(XSUAA.APP_ID, DEFAULT_XSUAA_PATH + "/xsappname");

        when(cut.getXsuaaBindings()).thenReturn(new File[] {xsuaaInstance1,xsuaaInstance2});
        when(cut.extractSingleXsuaaBindingFiles(new File[] {xsuaaInstance1,xsuaaInstance2})).thenReturn(new File[] {clientId,clientSecret,url,appId});
        when(cut.getLinesFromFile(clientId)).thenReturn(Collections.singletonList("myClientId"));
        when(cut.getLinesFromFile(clientSecret)).thenReturn(Collections.singletonList("mySecret"));
        when(cut.getLinesFromFile(url)).thenReturn(Collections.singletonList("https://auth.sap.com"));
        when(cut.getLinesFromFile(appId)).thenReturn(Collections.singletonList("myAppName"));

        when(cut.getXsuaaServiceProperties()).thenCallRealMethod();
        when(cut.extractServiceProperties(anyList())).thenCallRealMethod();
        when(cut.getIasServiceProperties()).thenCallRealMethod();
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

    @Test
    void getFilesFromCustomPath() {
        Path resourceDirectory = Paths.get("src","test","resources");
        String customPath = resourceDirectory.toFile().getAbsolutePath();
        K8SServiceConfigurationAccessor cut = new K8SServiceConfigurationAccessor(customPath);
        File[] bindings = cut.getXsuaaBindings();
        assertThat(bindings[0].getAbsolutePath(), startsWith(customPath));
    }

    private static File mockFile(final String name, final String absolutePath) {
        File file = Mockito.mock(File.class);
        when(file.isFile()).thenReturn(true);
        when(file.getName()).thenReturn(name);
        when(file.getAbsolutePath()).thenReturn(absolutePath);
        return file;
    }
}