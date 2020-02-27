package com.sap.cloud.security.cas.client;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

/**
 * TODO: extract as library
 */
public class DefaultADCService implements ADCService {
        private static final Logger LOGGER = LoggerFactory.getLogger(DefaultADCService.class);

        private final CloseableHttpClient httpClient;

        public DefaultADCService() {
            this.httpClient = HttpClients.createDefault();
        }

        public DefaultADCService(CloseableHttpClient client) {
            this.httpClient = client;
        }

        @Override
        public OpenPolicyAgentResponse isUserAuthorized(URI adcUri, OpenPolicyAgentRequest request) {
           // TODO
            throw new UnsupportedOperationException("Apache Http client not yet supported.");
        }

        public boolean ping(URI adcUri) {
            throw new UnsupportedOperationException("Apache Http client not yet supported.");
        }

}
