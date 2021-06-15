package com.sap.cloud.security.xsuaa.mtls;

import com.sap.cloud.security.config.ClientIdentity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 * SpringHttpClient provides factory methods to initialize RestTemplate for
 * certificate(HTTPS) based and client secret(HTTP) based communications.
 */
public class SpringHttpClient {

	private SpringHttpClient() {
	}

	/**
	 * Creates a HTTP RestTemplate
	 * 
	 * @return RestTemplate instance
	 */
	public static RestTemplate create() {
		return new RestTemplate();
	}

	/**
	 * Creates a HTTPS RestTemplate. Used to setup HTTPS client for X.509
	 * certificate based communication. Derives certificate and private key values
	 * from ClientIdentity.
	 *
	 * @param clientIdentity
	 *            ClientIdentity of Xsuaa Service
	 * @return RestTemplate instance
	 * @throws ServiceClientException
	 *             if ClientIdentity wasn't certificate based
	 */
	public static RestTemplate create(ClientIdentity clientIdentity) throws ServiceClientException {
		if (clientIdentity.isCertificateBased()) {
			HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
			requestFactory.setHttpClient(HttpClient.create(clientIdentity));

			return new RestTemplate(requestFactory);
		}

		throw new ServiceClientException("ClientIdentity is not certificate based, can't initiate mTLS http client");
	}
}
