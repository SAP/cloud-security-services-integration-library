/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Nullable;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class XsuaaOAuth2SMService implements OAuth2SMService {

    private static final Logger LOGGER = LoggerFactory.getLogger(XsuaaOAuth2SMService.class);
    private static final String SERVICE_PLANS = "/v1/service_plans";
    private static final String SERVICE_INSTANCES = "/v1/service_instances";

    private final RestOperations restOperations;
    private final OAuth2ServiceConfiguration smConfiguration;
    private final XsuaaOAuth2TokenService tokenService;

    public XsuaaOAuth2SMService(OAuth2ServiceConfiguration smConfiguration, @Nullable RestOperations restOperations) {
        this.smConfiguration = smConfiguration;
        this.restOperations = restOperations != null ? restOperations : new RestTemplate();
        this.tokenService = new XsuaaOAuth2TokenService(this.restOperations);
    }

    @Override
    public Map<String, String> getServicePlans() {
        Map<String, String> servicePlanMap = new HashMap<>();
        try {
            JSONArray responseArray = handleResponse(executeRequest(SERVICE_PLANS));
            responseArray.forEach(plan -> servicePlanMap.put((String) ((JSONObject) plan).get("id"), (String) ((JSONObject) plan).get("name")));
        } catch (OAuth2ServiceException e) {
            e.printStackTrace();
        }
        LOGGER.debug("Service plans: {}", servicePlanMap);
        return servicePlanMap;
    }

    @Override
    public Map<String, String> getServiceInstances() {
        Map<String, String> serviceInstanceMap = new HashMap<>();
        try {
            JSONArray responseArray = handleResponse(executeRequest(SERVICE_INSTANCES));
            responseArray.forEach(plan -> serviceInstanceMap.put((String) ((JSONObject) plan).get("name"), (String) ((JSONObject) plan).get("service_plan_id")));
        } catch (OAuth2ServiceException e) {
            e.printStackTrace();
        }
        LOGGER.debug("Service instances: {}", serviceInstanceMap);
        return serviceInstanceMap;
    }

    @Override
    public Map<String, String> getServiceInstancePlans() {
        Map<String, String> servicePlans = getServicePlans();
        Map<String, String> serviceInstances = getServiceInstances();
        serviceInstances.keySet().forEach(k -> serviceInstances.put(k, servicePlans.get(serviceInstances.get(k))));
        LOGGER.debug("Service Instances with plan names: {}", serviceInstances);
        return serviceInstances;
    }

    public ResponseEntity<String> executeRequest(String apiPath) {
        URI uri = URI.create(smConfiguration.getProperty("sm_url") + apiPath);
                LOGGER.debug("Executing Http request to {}", uri);

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + retrieveAccessToken());
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restOperations.exchange(uri, HttpMethod.GET, entity, String.class);
        LOGGER.debug("Received statusCode {} from {} with body {}", response.getStatusCode(), uri, response.getBody());
        return response;
    }

    private JSONArray handleResponse(ResponseEntity<String> response) throws OAuth2ServiceException {
        if (response.getStatusCode().is2xxSuccessful()) {
            return new JSONObject(response.getBody()).getJSONArray("items");
        } else {
            throw OAuth2ServiceException.builder("Error accessing service-manager endpoint")
                    .withStatusCode(response.getStatusCodeValue())
                    .withResponseBody(response.getBody())
                    .build();
        }
    }

    @Nullable
    private String retrieveAccessToken() {
        try {
            OAuth2TokenResponse oAuth2TokenResponse = tokenService
                    .retrieveAccessTokenViaClientCredentialsGrant(smConfiguration.getUrl().resolve("/oauth/token"), smConfiguration.getClientIdentity(), null, null, null, false);
            return oAuth2TokenResponse.getAccessToken();
        } catch (OAuth2ServiceException e) {
            LOGGER.warn("Couldn't retrieve access token for service manager.", e);
            return null;
        }
    }
}
