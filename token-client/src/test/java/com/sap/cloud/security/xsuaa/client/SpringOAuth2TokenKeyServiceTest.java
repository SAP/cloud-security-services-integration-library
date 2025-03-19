/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.client.SpringTokenClientConfiguration;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpMethod.GET;

public class SpringOAuth2TokenKeyServiceTest {

    public static final URI TOKEN_KEYS_ENDPOINT_URI = URI.create("https://token.endpoint.io/token_keys");
    public static final String APP_TID = "92768714-4c2e-4b79-bc1b-009a4127ee3c";
    public static final String CLIENT_ID = "client-id";
    public static final String AZP = "azp";
    public static final String ERROR_MESSAGE = "useful error message";
    private static final Map<String, String> PARAMS = Map.of(
            HttpHeaders.X_APP_TID, APP_TID,
            HttpHeaders.X_CLIENT_ID, CLIENT_ID,
            HttpHeaders.X_AZP, AZP);
    private final String jsonWebKeysAsString;
    private RestOperations restOperationsMock;
    private SpringOAuth2TokenKeyService cut;

    public SpringOAuth2TokenKeyServiceTest() throws IOException {
        jsonWebKeysAsString = IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
    }

    @Before
    public void setUp() {
        restOperationsMock = mock(RestOperations.class);
        setupRetryConfiguration();
        cut = new SpringOAuth2TokenKeyService(restOperationsMock);
    }

    @Test
    public void restOperations_isNull_throwsException() {
        assertThatThrownBy(() -> new SpringOAuth2TokenKeyService(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void retrieveTokenKeys_endpointUriIsNull_throwsException() {
        assertThatThrownBy(() -> cut.retrieveTokenKeys(null, APP_TID))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void retrieveTokenKeys_usesGivenURI() throws OAuth2ServiceException {
        mockResponse();

        cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

        Mockito.verify(restOperationsMock, times(1))
                .exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), argThat(httpEntityContainsMandatoryHeaders()),
                        eq(String.class));
    }

    @Test
    public void retrieveTokenKeys_badResponse_throwsException() {
        mockResponse(ERROR_MESSAGE, HttpStatus.BAD_REQUEST);

        final OAuth2ServiceException e = assertThrows(OAuth2ServiceException.class,
                () -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS));

        assertThat(e.getMessage())
                .contains(TOKEN_KEYS_ENDPOINT_URI.toString())
                .contains(String.valueOf(HttpStatus.BAD_REQUEST.value()))
                .contains("Request headers [Accept: application/json, User-Agent: token-client/")
                .contains("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
                .contains("x-client_id: client-id")
                .contains("x-azp: azp")
                .contains("Response Headers ")
                .contains(ERROR_MESSAGE);
        assertThat(e.getHttpStatusCode()).isEqualTo(400);
        assertThat(e.getHeaders()).hasSize(1);
        assertThat(e.getHeaders()).contains("Content-Type: application/json");
    }

    @Test
    public void retrieveTokenKeys_responseAndRetryWithInternalServerError_throwsException() {
        mockResponse(ERROR_MESSAGE, HttpStatus.INTERNAL_SERVER_ERROR);
        final SpringTokenClientConfiguration config = SpringTokenClientConfiguration.getConfig();
        config.setRetryEnabled(true);

        final OAuth2ServiceException e = assertThrows(OAuth2ServiceException.class,
                () -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS));

        assertThat(e.getMessage())
                .contains(TOKEN_KEYS_ENDPOINT_URI.toString())
                .contains(String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value()))
                .contains("Request headers [Accept: application/json, User-Agent: token-client/")
                .contains("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
                .contains("x-client_id: client-id")
                .contains("x-azp: azp")
                .contains("Response Headers ")
                .contains(ERROR_MESSAGE);
        assertThat(e.getHttpStatusCode()).isEqualTo(500);
        assertThat(e.getHeaders()).hasSize(1);
        assertThat(e.getHeaders()).contains("Content-Type: application/json");
        Mockito.verify(restOperationsMock, times(2))
                .exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(),
                        eq(String.class));
    }

    @Test
    public void retrieveTokenKeys_responseNotOkAndNoRetryAsStatusIsNotRetryable_throwsException() {
        mockResponse(ERROR_MESSAGE, HttpStatus.BAD_REQUEST);
        final SpringTokenClientConfiguration config = SpringTokenClientConfiguration.getConfig();
        config.setRetryEnabled(true);

        final OAuth2ServiceException e = assertThrows(OAuth2ServiceException.class,
                () -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS));

        assertThat(e.getMessage())
                .contains(TOKEN_KEYS_ENDPOINT_URI.toString())
                .contains(String.valueOf(HttpStatus.BAD_REQUEST.value()))
                .contains("Request headers [Accept: application/json, User-Agent: token-client/")
                .contains("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
                .contains("x-client_id: client-id")
                .contains("x-azp: azp")
                .contains("Response Headers ")
                .contains(ERROR_MESSAGE);
        assertThat(e.getHttpStatusCode()).isEqualTo(400);
        assertThat(e.getHeaders()).hasSize(1);
        assertThat(e.getHeaders()).contains("Content-Type: application/json");
        Mockito.verify(restOperationsMock, times(1))
                .exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(),
                        eq(String.class));
    }

    @Test
    public void retrieveTokenKeys_errorOccursDuringRetry_throwsServiceException() {
        final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Content-Type", "application/json");
        final ResponseEntity<String> internalServerErrorResponse = new ResponseEntity<>(ERROR_MESSAGE, headers, HttpStatus.INTERNAL_SERVER_ERROR);
        final ResponseEntity<String> badRequestResponse = new ResponseEntity<>(ERROR_MESSAGE, headers, HttpStatus.BAD_REQUEST);
        when(restOperationsMock.exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(internalServerErrorResponse).thenReturn(badRequestResponse);
        final SpringTokenClientConfiguration config = SpringTokenClientConfiguration.getConfig();
        config.setRetryEnabled(true);

        final OAuth2ServiceException e = assertThrows(OAuth2ServiceException.class,
                () -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS));

        assertThat(e.getMessage())
                .contains(TOKEN_KEYS_ENDPOINT_URI.toString())
                .contains(String.valueOf(HttpStatus.BAD_REQUEST.value()))
                .contains("Request headers [Accept: application/json, User-Agent: token-client/")
                .contains("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
                .contains("x-client_id: client-id")
                .contains("x-azp: azp")
                .contains("Response Headers ")
                .contains(ERROR_MESSAGE);
        assertThat(e.getHttpStatusCode()).isEqualTo(400);
        assertThat(e.getHeaders()).hasSize(1);
        assertThat(e.getHeaders()).contains("Content-Type: application/json");
        Mockito.verify(restOperationsMock, times(2))
                .exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(),
                        eq(String.class));
    }

    @Test
    public void retrieveTokenKeys_retryTimeoutIsTooLongSoRetryWithThreshold_executesRetrySuccessfully() throws IOException {
        final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Content-Type", "application/json");
        final ResponseEntity<String> internalServerErrorResponse = new ResponseEntity<>(ERROR_MESSAGE, headers, HttpStatus.INTERNAL_SERVER_ERROR);
        final ResponseEntity<String> okResponse = new ResponseEntity<>(jsonWebKeysAsString, headers, HttpStatus.OK);
        when(restOperationsMock.exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(internalServerErrorResponse).thenReturn(okResponse);
        final SpringTokenClientConfiguration config = SpringTokenClientConfiguration.getConfig();
        config.setRetryEnabled(true);
        config.setRetryDelayTime(1500000L);

        final long start = System.currentTimeMillis();
        final String result = cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);
        final long duration = System.currentTimeMillis() - start;

        Mockito.verify(restOperationsMock, times(2)).exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(),
                eq(String.class));
        assertThat(duration).isLessThan(config.getRetryDelayTime());
        assertThat(result).isNotEmpty();
    }

    @Test
    public void retrieveTokenKeys_responseNotOk_retry_executesRetrySuccessfully() throws IOException {
        final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Content-Type", "application/json");
        final ResponseEntity<String> internalServerErrorResponse = new ResponseEntity<>(ERROR_MESSAGE, headers, HttpStatus.INTERNAL_SERVER_ERROR);
        final ResponseEntity<String> okResponse = new ResponseEntity<>(jsonWebKeysAsString, headers, HttpStatus.OK);
        when(restOperationsMock.exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(internalServerErrorResponse).thenReturn(okResponse);
        final SpringTokenClientConfiguration config = SpringTokenClientConfiguration.getConfig();
        config.setRetryEnabled(true);

        final String result = cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

        Mockito.verify(restOperationsMock, times(2)).exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(),
                eq(String.class));
        assertThat(result).isNotEmpty();
    }

    private void mockResponse() {
        mockResponse(jsonWebKeysAsString, HttpStatus.OK);
    }

    private void mockResponse(final String responseAsString, final HttpStatus httpStatus) {
        final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Content-Type", "application/json");
        final ResponseEntity<String> stringResponseEntity = new ResponseEntity<>(responseAsString, headers, httpStatus);
        when(restOperationsMock.exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(stringResponseEntity);
    }

    private ArgumentMatcher<HttpEntity> httpEntityContainsMandatoryHeaders() {
        return (httpGet) -> {
            final boolean correctClientId = httpGet.getHeaders().get(HttpHeaders.X_CLIENT_ID).get(0).equals(CLIENT_ID);
            final boolean correctAppTid = httpGet.getHeaders().get(HttpHeaders.X_APP_TID).get(0).equals(APP_TID);
            final boolean correctAzp = httpGet.getHeaders().get(HttpHeaders.X_AZP).get(0).equals(AZP);
            return correctAppTid && correctClientId && correctAzp;
        };
    }

    private void setupRetryConfiguration() {
        final SpringTokenClientConfiguration springTokenClientConfiguration = new SpringTokenClientConfiguration();
        springTokenClientConfiguration.setRetryStatusCodes("408,429,500,502,503,504");
        springTokenClientConfiguration.setMaxRetryAttempts(1);
        springTokenClientConfiguration.setRetryEnabled(false);
        springTokenClientConfiguration.setRetryDelayTime(100);
        SpringTokenClientConfiguration.setConfig(springTokenClientConfiguration);
    }
}