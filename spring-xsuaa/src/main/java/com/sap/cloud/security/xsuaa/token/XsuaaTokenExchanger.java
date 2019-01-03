/**
 * Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License,
 * v. 2 except as noted otherwise in the LICENSE file
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.cloud.security.xsuaa.token;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.sap.xs2.security.container.UserInfoException;
import com.sap.xsa.security.container.XSTokenRequest;

import net.minidev.json.JSONObject;

public class XsuaaTokenExchanger {
    Token token;
    RestTemplate restTemplate;

    XsuaaTokenExchanger(RestTemplate restTemplate, Token token) {
        Assert.notNull(token, "token is required");
        this.token = token;
        this.restTemplate = restTemplate != null ? restTemplate : new RestTemplate();
    }

    /**
     * Exchange a token into a token from another service instance
     *
     * @param tokenRequest
     *            request data
     * @throws URISyntaxException
     * 			   in case of inconsistent urls
     * @throws UserInfoException
     * 			   in case of token exchange errors
     * @return requested token
     */
    public String requestToken(XSTokenRequest tokenRequest) throws UserInfoException, URISyntaxException {
        Assert.isTrue(tokenRequest.isValid(), "Invalid grant type or missing parameters for requested grant type.");
        // build authorities string for additional authorization attributes
        String authorities = null;
        if (tokenRequest.getAdditionalAuthorizationAttributes() != null) {
            Map<String, Object> azAttrMap = new HashMap<>();
            azAttrMap.put("az_attr", tokenRequest.getAdditionalAuthorizationAttributes());
            StringBuilder azStringBuilder = new StringBuilder();
            try {
                JSONObject.writeJSON(azAttrMap, azStringBuilder);
            } catch (IOException e) {
                throw new UserInfoException("Error creating json representation", e);
            }
            authorities = azStringBuilder.toString();
        }
        // check whether token endpoint has the correct subdomain, if not replace it with the subdomain of the token
        String tokenSubdomain = token.getSubdomain();
        String tokenRequestSubdomain = getSubdomain(tokenRequest.getTokenEndpoint().toString());
        if (tokenSubdomain != null && tokenRequestSubdomain != null && !tokenSubdomain.equals(tokenRequestSubdomain)) {
            tokenRequest.setTokenEndpoint(replaceSubdomain(tokenRequest.getTokenEndpoint(), tokenSubdomain));
        }
        // request the token based on the type
        switch (tokenRequest.getType()) {
            case XSTokenRequest.TYPE_USER_TOKEN:
                return requestTokenNamedUser(tokenRequest.getClientId(), tokenRequest.getClientSecret(), tokenRequest.getTokenEndpoint().toString(), authorities);
            case XSTokenRequest.TYPE_CLIENT_CREDENTIALS_TOKEN:
                return requestTokenTechnicalUser(tokenRequest, authorities);
            default:
                throw new UserInfoException("Invalid grant type.");
        }
    }

    /**
     * Replace the subdomain in the given uri with the given subdomain
     * @param uri
     * 		 uri
     * @param subdomain
     * 		 subdomain
     * @return subdomain
     */
    protected URI replaceSubdomain(URI uri, String subdomain) {
        if (uri == null || subdomain == null || !uri.getHost().contains(".")) {
            return null;
        }
        UriComponentsBuilder builder = UriComponentsBuilder.newInstance().scheme(uri.getScheme()).host(subdomain + uri.getHost().substring(uri.getHost().indexOf("."))).port(uri.getPort()).path(uri.getPath());
        return uri.resolve(builder.build().toString());
    }

    private String requestTokenTechnicalUser(XSTokenRequest tokenRequest, String authorities) throws UserInfoException {
        // note: consistency checks (clientid, clientsecret and url) have already been executed
        // build uri for client credentials flow
        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenRequest.getTokenEndpoint()).queryParam("grant_type", "client_credentials");
        if (authorities != null) {
            builder.queryParam("authorities", authorities);
        }
        // build http headers
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.ACCEPT, "application/json");
        String credentials = tokenRequest.getClientId() + ":" + tokenRequest.getClientSecret();
        String base64Creds = Base64.getEncoder().encodeToString(credentials.getBytes());
        headers.add(HttpHeaders.AUTHORIZATION, "Basic " + base64Creds);
        HttpEntity<Map> entity = new HttpEntity<Map>(headers);
        // request the token
        ResponseEntity<Map> responseEntity = restTemplate.postForEntity(builder.build().encode().toUri(), entity, Map.class);
        if (responseEntity.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            throw new UserInfoException("Call to /oauth/token was not successful (grant_type: client_credentials). Client credentials invalid");
        }
        if (responseEntity.getStatusCode() != HttpStatus.OK) {
            throw new UserInfoException("Call to /oauth/token was not successful (grant_type: client_credentials). HTTP status code: " + responseEntity.getStatusCode());
        }
        return responseEntity.getBody().get("access_token").toString();
    }

    private String requestTokenNamedUser(String serviceClientId, String serviceClientSecret, String serviceUaaUrl, String authorities) throws UserInfoException {
        // consistency checks
        if (serviceClientId == null || serviceClientSecret == null) {
            throw new UserInfoException("Invalid service credentials: Missing clientid/clientsecret.");
        }
        if (serviceUaaUrl == null) {
            throw new UserInfoException("Invalid service credentials: Missing url.");
        }
        if (!checkScope("uaa.user")) {
            throw new UserInfoException("JWT token does not include scope 'uaa.user'.");
        }
        // build uri for user token flow
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(serviceUaaUrl).queryParam("grant_type", "user_token").queryParam("response_type", "token").queryParam("client_id", serviceClientId);
        if (authorities != null) {
            builder.queryParam("authorities", authorities);
        }
        // build http headers
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.ACCEPT, "application/json");
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + token.getAppToken());
        HttpEntity<Map> entity = new HttpEntity<Map>(headers);
        // request the token
        ResponseEntity<Map> responseEntity = restTemplate.postForEntity(builder.build().encode().toUri(), entity, Map.class);
        if (responseEntity.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            throw new UserInfoException("Call to /oauth/token was not successful (grant_type: user_token). Bearer token invalid, requesting client does not have grant_type=user_token or no scopes were granted.");

        }
        if (responseEntity.getStatusCode() != HttpStatus.OK) {
            throw new UserInfoException("Call to /oauth/token was not successful (grant_type: user_token). HTTP status code: " + responseEntity.getStatusCode());

        }
        // build uri for refresh token flow
        builder = UriComponentsBuilder.fromHttpUrl(serviceUaaUrl).queryParam("grant_type", "refresh_token").queryParam("refresh_token", responseEntity.getBody().get("refresh_token").toString());
        // build http headers
        headers.clear();
        String credentials = serviceClientId + ":" + serviceClientSecret;
        String base64Creds = Base64.getEncoder().encodeToString(credentials.getBytes());
        headers.add(HttpHeaders.ACCEPT, "application/json");
        headers.add(HttpHeaders.AUTHORIZATION, "Basic " + base64Creds);
        entity = new HttpEntity<Map>(headers);
        // request the token
        responseEntity = restTemplate.postForEntity(builder.build().encode().toUri(), entity, Map.class);
        if (responseEntity.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            throw new UserInfoException("Call to /oauth/token was not successful (grant_type: refresh_token). Client credentials invalid");
        }
        if (responseEntity.getStatusCode() != HttpStatus.OK) {
            throw new UserInfoException("Call to /oauth/token was not successful (grant_type: refresh_token). HTTP status code: " + responseEntity.getStatusCode());
        }
        return responseEntity.getBody().get("access_token").toString();
    }

    /**
     * Get the subdomain from the given url
     *
     * @return subdomain
     */
    protected String getSubdomain(String url) {
        String host = null;
        try {
            host = new URI(url).getHost();
        } catch (URISyntaxException e) {
            return null;
        }
        if (host == null || !host.contains(".")) {
            return null;
        }
        return host.split("\\.")[0];
    }

    protected boolean checkScope(String scope) {
        List<String> scopes = ((TokenImpl) token).getClaimAccessor().getClaimAsStringList(TokenImpl.CLAIM_SCOPES);
        return scopes.contains(scope);
    }

}
