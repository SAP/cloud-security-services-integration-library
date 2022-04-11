package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class DefaultHttpClientFactoryTest {

    public static final HttpGet HTTP_GET = new HttpGet(java.net.URI.create("https://google.de"));
    private static ClientIdentity config = Mockito.mock(ClientIdentity.class);
    private static ClientIdentity config2 = Mockito.mock(ClientIdentity.class);
    private static DefaultHttpClientFactory cut = new DefaultHttpClientFactory();

    @BeforeAll
    static void setup() throws IOException {
        when(config.getId()).thenReturn("theClientId");
        when(config.getKey()).thenReturn(readFromFile("/privateRSAKey.txt"));
        when(config.getCertificate()).thenReturn( readFromFile("/certificates.txt"));
        when(config.isCertificateBased()).thenCallRealMethod();

        when(config2.getId()).thenReturn("theClientId-2");
        when(config2.getKey()).thenReturn(readFromFile("/privateRSAKey.txt"));
        when(config2.getCertificate()).thenReturn( readFromFile("/certificates.txt"));
        when(config2.isCertificateBased()).thenCallRealMethod();
    }

    @Test
    void createHttpClient_sameClientId() {
        HttpClient client1 = cut.createClient(config);
        HttpClient client2 = cut.createClient(config);

        assertNotEquals(client1, client2);
        assertNotEquals(client1.getConnectionManager(), client2.getConnectionManager()); // different InternalHttpClient instances
        assertEquals(1, cut.sslConnectionPool.size());
    }

    @Test
    void createHttpClient_differentClientId() {
        HttpClient client1 = cut.createClient(config);
        HttpClient client2 = cut.createClient(config2);

        assertNotEquals(client1, client2);
        assertNotEquals(client1.getConnectionManager(), client2.getConnectionManager()); // different InternalHttpClient instances
        assertEquals(2, cut.sslConnectionPool.size());
    }

    @Test
    void closeHttpClient_sameClientId() throws IOException {
        CloseableHttpClient client1 = cut.createClient(config);
        HttpClient client2 = cut.createClient(config2);

        HttpResponse response = client1.execute(HTTP_GET);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        client1.close();

        assertThrows(IllegalStateException.class, () -> client1.execute(HTTP_GET));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        response = client2.execute(HTTP_GET);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    private static String readFromFile(String file) throws IOException {
        return IOUtils.resourceToString(file, StandardCharsets.UTF_8);
    }
}