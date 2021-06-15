package com.sap.cloud.security.xsuaa.mtls;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientIdentity;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * HttpClient provides factory methods to initialize HTTP or HTTPS client based
 * on ClientIdentity provided.
 */
public class HttpClient {

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpClient.class);

	private HttpClient() {
	}

	/**
	 * Provides CloseableHttpClient based on ClientIdentity details. For
	 * ClientIdentity that is certificate based it will resolve https client using
	 * the provided ClientIdentity in the {@link #create(ClientIdentity)} If the
	 * ClientIdentity wasn't provided it will return default HttpClient.
	 * 
	 * @param clientIdentity
	 *            for X.509 certificate based communication
	 *            {@link ClientCertificate} implementation of ClientIdentity
	 *            interface should be provided
	 * @return HTTP or HTTPS client
	 * @throws ServiceClientException
	 *         in case HTTPS Client could not be setup
	 */
	public static CloseableHttpClient create(@Nullable ClientIdentity clientIdentity) throws ServiceClientException {
		return getCloseableHttpClient(clientIdentity);
	}

	/**
	 * Provides CloseableHttpClient based on ClientIdentity details. For
	 * ClientIdentity that is certificate based it will resolve https client using
	 * the provided ClientIdentity in the {@link #create(ClientIdentity)} If the
	 * ClientIdentity wasn't provided it will return default HttpClient
	 * 
	 * @return HTTP or HTTPS client
	 * @throws ServiceClientException
	 *             in case HTTPS Client could not be setup
	 */
	private static CloseableHttpClient getCloseableHttpClient(ClientIdentity clientIdentity) throws ServiceClientException {
		if (clientIdentity != null && clientIdentity.isCertificateBased()) {
			LOGGER.debug("Setting up HTTPS client with: clientId: {}\ncertificate: {}\nprivate key: {}\n",
					clientIdentity.getId(), clientIdentity.getCertificate(), clientIdentity.getKey());

			SSLContext sslContext;
			try {
				sslContext = SSLContextFactory.getInstance().create(clientIdentity.getCertificate(),
						clientIdentity.getKey());
			} catch (IOException | GeneralSecurityException e) {
				throw new ServiceClientException(
						String.format("Couldn't set up HTTPS client for service provider. %s.%s", e.getMessage(), e));
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
