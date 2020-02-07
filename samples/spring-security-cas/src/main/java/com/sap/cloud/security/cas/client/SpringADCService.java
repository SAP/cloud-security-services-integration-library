package com.sap.cloud.security.cas.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;

import java.net.URI;

/**
 * TODO: extract as library
 */
public class SpringADCService implements ADCService {
    private static final Logger LOGGER = LoggerFactory.getLogger(SpringADCService.class);

    private final RestOperations restOperations;

    public SpringADCService(RestOperations restOperations) {
        this.restOperations = restOperations;
    }

    @Override
    public OpenPolicyAgentResponse isUserAuthorized(URI adcUri, OpenPolicyAgentRequest request) {
        HttpEntity<?> httpRequest = new HttpEntity<>(request);
        try {
            return restOperations.postForObject(adcUri, httpRequest, OpenPolicyAgentResponse.class);
        } catch (RestClientException e) {
            LOGGER.error("Error accessing ADC service {}: {}.", adcUri, e.getCause(), e);
            return new OpenPolicyAgentResponse();
        }
    }
}
