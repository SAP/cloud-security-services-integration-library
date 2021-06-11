package com.sap.cloud.security.xsuaa.mtls;

import com.sap.cloud.security.client.ClientCertificate;
import com.sap.xsa.security.container.ClientIdentity;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * HttpClient provides factory methods to initialize HTTP or HTTPS client based on ClientIdentity provided.
 */
public class HttpClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpClient.class);
    private static HttpClient httpClient = null;
    private ClientIdentity clientIdentity;

    private HttpClient() {}

    /**
     * Default method to initialize HttpClient without any Client Identity details.
     * @return new HttpClient
     */
    public static HttpClient create() {
        if (httpClient == null){
            httpClient = new HttpClient();
        }
        return httpClient;
    }

    /**
     * Initializes HttpClient with ClientIdentity. Used to setup HTTPS client for X.509 certificate based communication.
     * @param clientIdentity for X.509 certificate based communication {@link ClientCertificate} implementation of ClientIdentity interface should be provided
     * @return httpClient
     */
    public static HttpClient create(ClientIdentity clientIdentity) {
        create();
        httpClient.clientIdentity = clientIdentity;
        return httpClient;
    }

    /**
     * Provides CloseableHttpClient based on ClientIdentity details. For ClientIdentity that is certificate based it will resolve https client
     * using the provided ClientIdentity in the {@link #create(ClientIdentity)} If the ClientIdentity wasn't provided it will return default HttpClient
     * @return HTTP or HTTPS client
     * @throws ServiceClientException in case HTTPS Client could not be setup
     */
    public CloseableHttpClient getCloseableHttpClient() throws ServiceClientException {
        if (clientIdentity != null  && clientIdentity.isCertificateBased()){
            LOGGER.debug("Setting up HTTPS client with: clientId: {}\ncertificate: {}\nprivate key: {}\n", clientIdentity.getId(), clientIdentity.getCertificate(), clientIdentity.getKey());

            SSLContext sslContext;
            try {
                sslContext = SSLContextFactory.getInstance().create(clientIdentity.getCertificate(), clientIdentity.getKey());
            } catch (IOException | GeneralSecurityException e) {
                throw new ServiceClientException(String.format("Couldn't set up HTTPS client for service provider. %s.%s", e.getMessage(), e));
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
