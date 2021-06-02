package com.sap.cloud.security.xsuaa.mtls;

import com.sap.xsa.security.container.ClientIdentity;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class HttpClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpClient.class);
    private static HttpClient httpClient = null;
    private ClientIdentity clientIdentity;

    private HttpClient() {}

    public static HttpClient create() {
        if (httpClient == null){
            httpClient = new HttpClient();
        }
        return httpClient;
    }

    public static HttpClient create(ClientIdentity clientIdentity) {
        create();
        httpClient.clientIdentity = clientIdentity;
        return httpClient;
    }

    public CloseableHttpClient getCloseableHttpClient() throws ServiceClientException {
        if (clientIdentity != null  && clientIdentity.isCertificateBased()){
            LOGGER.debug("Cert, key, clientId from Xsuaa binding {}\n {}\n {}", clientIdentity.getCertificate(), clientIdentity.getKey(), clientIdentity.getId());

            SSLContext sslContext;
            try {
                sslContext = SSLContextFactory.getInstance().create(clientIdentity.getCertificate(), clientIdentity.getKey());
            } catch (IOException | GeneralSecurityException e) {
                throw new ServiceClientException(String.format("Couldn't set up Https client for service provider. %s.%s", e.getMessage(), e));
            }

            SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);

            return HttpClients.custom()
                    .setSSLContext(sslContext)
                    .setSSLSocketFactory(socketFactory)
                    .build();
        } else {
            return HttpClients.createDefault();
        }
    }
}
