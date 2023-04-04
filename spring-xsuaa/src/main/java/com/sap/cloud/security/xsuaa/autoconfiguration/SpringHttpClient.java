package com.sap.cloud.security.xsuaa.autoconfiguration;

import javax.annotation.Nullable;

import com.sap.cloud.security.client.SpringHttpClientFactory;
import com.sap.cloud.security.config.ClientIdentity;
import org.springframework.web.client.RestTemplate;

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
		return SpringHttpClientFactory.createRestTemplate(clientIdentity);
	}
}
