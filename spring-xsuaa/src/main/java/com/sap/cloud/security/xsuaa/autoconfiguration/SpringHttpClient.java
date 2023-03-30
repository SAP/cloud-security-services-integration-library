package com.sap.cloud.security.xsuaa.autoconfiguration;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.ClientIdentity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Nullable;

/**
 * SpringHttpClient provides factory method to initialize RestTemplate for
 * certificate (HTTPS) based communications.
 */
class SpringHttpClient {

	private SpringHttpClient() {
	}

	static SpringHttpClient getInstance() {
		return new SpringHttpClient();
	}

	/**
	 * Creates a HTTPS RestTemplate. Used to setup HTTPS client for X.509
	 * certificate based communication. Derives certificate and private key values
	 * from ClientIdentity.
	 *
	 * @param clientIdentity
	 *            ClientIdentity of Xsuaa Service
	 * @return RestTemplate instance
	 */
	public RestTemplate create(@Nullable ClientIdentity clientIdentity) {
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(HttpClientFactory.create(clientIdentity));
		return new RestTemplate(requestFactory);
	}
}
