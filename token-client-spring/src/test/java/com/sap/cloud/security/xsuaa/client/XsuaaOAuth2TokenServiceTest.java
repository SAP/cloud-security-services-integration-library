/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.ACCESS_TOKEN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.EXPIRES_IN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.REFRESH_TOKEN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.TOKEN_TYPE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.servlet.MDCHelper;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestOperations;

class XsuaaOAuth2TokenServiceTest {
    
  public static final URI TOKEN_KEYS_ENDPOINT_URI =
      URI.create("https://token.endpoint.io/token_keys");
  public static final String APP_TID = "92768714-4c2e-4b79-bc1b-009a4127ee3c";
  public static final String CLIENT_ID = "client-id";
  public static final String AZP = "azp";
  public static final String TEST_ACCESS_TOKEN = "Valid Access token";
  public static final String TEST_REFRESH_TOKEN = "Valid Refresh token";
  public static final String TEST_EXPIRATION_TIME = "1000";
  public static final String TEST_TOKEN_TYPE = "TOKEN TYPE";
  private static final Map<String, String> PARAMS =
      Map.of(
          HttpHeaders.X_APP_TID, APP_TID,
          HttpHeaders.X_CLIENT_ID, CLIENT_ID,
          HttpHeaders.X_AZP, AZP);
  private static final Map<String, String> responseBody =
      Map.of(
          ACCESS_TOKEN, TEST_ACCESS_TOKEN,
          EXPIRES_IN, TEST_EXPIRATION_TIME,
          REFRESH_TOKEN, TEST_REFRESH_TOKEN,
          TOKEN_TYPE, TEST_TOKEN_TYPE);
  private RestOperations restOperationsMock;
  private XsuaaOAuth2TokenService cut;
  private HttpHeaders headers;

  @BeforeEach
  public void setUp() {
    restOperationsMock = Mockito.mock(RestOperations.class);
    cut = new XsuaaOAuth2TokenService(restOperationsMock);
    headers = new HttpHeaders();
  }

  @Test
  void initialize_throwsIfRestOperationsIsNull() {
    assertThatThrownBy(
            () -> new XsuaaOAuth2TokenService(null, TokenCacheConfiguration.cacheDisabled()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void initialize_throwsIfCacheConfigurationIsNull() {
    assertThatThrownBy(() -> new XsuaaOAuth2TokenService(Mockito.mock(RestOperations.class), null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void retrieveTokenKeys_responseNotOk_throwsException() {
    mockResponse(responseBody, 500);
    setConfigurationValues(0, Set.of());

    assertThatThrownBy(() -> cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("User-Agent: token-client/")
        .hasMessageContaining("expires_in=1000")
        .hasMessageContaining("access_token=Valid Access token")
        .hasMessageContaining("token_type=TOKEN TYPE")
        .hasMessageContaining("Server error while obtaining access token from XSUAA!")
        .hasMessageContaining("Http status code 500");
  }

  @Test
  public void retrieveTokenKeys_httpClientExceptionOccurs_throwsServiceException() {
    when(restOperationsMock.postForEntity(eq(TOKEN_KEYS_ENDPOINT_URI), any(), eq(Map.class)))
        .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST) {});

    assertThatThrownBy(() -> cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(
            "Client error retrieving JWT token. Call to XSUAA was not successful!")
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageNotContaining("Response Headers [")
        .hasMessageContaining("Http status code 400");
  }

  @Test
  public void retrieveTokenKeys_httpServerErrorExceptionOccurs_throwsServiceException() {
    when(restOperationsMock.postForEntity(eq(TOKEN_KEYS_ENDPOINT_URI), any(), eq(Map.class)))
        .thenThrow(new HttpServerErrorException(HttpStatus.BAD_REQUEST) {});

    assertThatThrownBy(() -> cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("Server error while obtaining access token from XSUAA!")
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageNotContaining("Response Headers [")
        .hasMessageContaining("Http status code 400");
  }

  @Test
  public void retrieveTokenKeys_resourceAccessExceptionOccurs_throwsServiceException() {
    when(restOperationsMock.postForEntity(eq(TOKEN_KEYS_ENDPOINT_URI), any(), eq(Map.class)))
        .thenThrow(new ResourceAccessException("Error accessing resource!") {});

    assertThatThrownBy(() -> cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("Error accessing resource!")
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageNotContaining("Response Headers [")
        .hasMessageContaining(
            "RestClient isn't configured properly - Error while obtaining access token from XSUAA!");
  }

  @Test
  public void retrieveTokenKeys_errorOccursDuringRetry_throwsServiceException() {
    mockResponse(responseBody, 500, 400);
    setConfigurationValues(10, Set.of(500));

    assertThatThrownBy(() -> cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("User-Agent: token-client/")
        .hasMessageContaining("expires_in=1000")
        .hasMessageContaining("access_token=Valid Access token")
        .hasMessageContaining("token_type=TOKEN TYPE")
        .hasMessageContaining("Server error while obtaining access token from XSUAA!")
        .hasMessageContaining("Http status code 400");

    Mockito.verify(restOperationsMock, times(2))
        .postForEntity(eq(TOKEN_KEYS_ENDPOINT_URI), any(), eq(Map.class));
  }

  @Test
  public void retrieveTokenKeys_executesCorrectHttpGetRequest() throws OAuth2ServiceException {
    mockResponse(responseBody, 200);

    cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS);

    Mockito.verify(restOperationsMock, times(1))
        .postForEntity(
            eq(TOKEN_KEYS_ENDPOINT_URI),
            argThat(httpEntityContainsMandatoryHeadersAndBody()),
            eq(Map.class));
  }

  @Test
  public void retrieveTokenKeys_withEmptyParams_executesSuccessfully()
      throws OAuth2ServiceException {
    mockResponse(responseBody, 200);

    final Map<String, String> emptyParams = Map.of();
    final OAuth2TokenResponse result =
        cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, emptyParams);

    assertThat(result).isNotNull();
    Mockito.verify(restOperationsMock, times(1))
        .postForEntity(eq(TOKEN_KEYS_ENDPOINT_URI), any(), eq(Map.class));
  }

  @Test
  void requestAccessToken_successfulResponse_returnsTokenResponse() throws OAuth2ServiceException {
    mockResponse(responseBody, 200);

    final OAuth2TokenResponse result =
        cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS);

    assertThat(result).isNotNull();
    assertThat(result.getAccessToken()).isEqualTo(TEST_ACCESS_TOKEN);
    assertThat(result.getRefreshToken()).isEqualTo(TEST_REFRESH_TOKEN);
    assertThat(result.getTokenType()).isEqualTo(TEST_TOKEN_TYPE);
    assertThat(result.getExpiredAt()).isAfter(Instant.now());
  }

  @Test
  public void
      retrieveTokenKeys_numberFormatExceptionWhileParsingExpiresIn_throwsServiceException() {
    mockResponse(Map.of(ACCESS_TOKEN, TEST_ACCESS_TOKEN, EXPIRES_IN, "STRING"), 200);

    assertThatThrownBy(() -> cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("Invalid expires_in value")
        .hasMessageNotContaining("Request Headers [")
        .hasMessageNotContaining("Response Headers [")
        .hasMessageContaining("Response body 'For input string: \"STRING\"'");
  }

  @Test
  void retrieveTokenKeys_responseNotOk_retry_executesRetrySuccessfully() throws IOException {
    mockResponse(responseBody, 500, 200);
    setConfigurationValues(1, Set.of(500));

    final OAuth2TokenResponse result =
        cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS);

    Mockito.verify(restOperationsMock, times(2))
        .postForEntity(eq(TOKEN_KEYS_ENDPOINT_URI), any(), eq(Map.class));
    assertThat(result).isNotNull();
  }

  @Test
  void retrieveTokenKeys_allRetryableStatusCodes_executesRetrySuccessfullyWithBadResponse() {
    mockResponse(responseBody, 408, 429, 500, 502, 503, 504, 400);
    setConfigurationValues(10, Set.of(408, 429, 500, 502, 503, 504));

    assertThatThrownBy(() -> cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("User-Agent: token-client/")
        .hasMessageContaining("expires_in=1000")
        .hasMessageContaining("access_token=Valid Access token")
        .hasMessageContaining("token_type=TOKEN TYPE")
        .hasMessageContaining("Server error while obtaining access token from XSUAA!")
        .hasMessageContaining("Http status code 400");
    Mockito.verify(restOperationsMock, times(7))
        .postForEntity(eq(TOKEN_KEYS_ENDPOINT_URI), any(), eq(Map.class));
  }

  @Test
  public void retrieveTokenKeys_noRetryableStatusCodesSet_executesNoRetry() {
    mockResponse(responseBody, 500);
    setConfigurationValues(10, Set.of());

    assertThatThrownBy(() -> cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("User-Agent: token-client/")
        .hasMessageContaining("expires_in=1000")
        .hasMessageContaining("access_token=Valid Access token")
        .hasMessageContaining("token_type=TOKEN TYPE")
        .hasMessageContaining("Server error while obtaining access token from XSUAA!")
        .hasMessageContaining("Http status code 500");
    Mockito.verify(restOperationsMock, times(1))
        .postForEntity(eq(TOKEN_KEYS_ENDPOINT_URI), any(), eq(Map.class));
  }

  @Test
  public void retrieveTokenKeys_retryLogic_maxAttemptsReached_throwsException() {
    mockResponse(responseBody, 500, 500, 500, 500);
    setConfigurationValues(2, Set.of(500));

    assertThatThrownBy(() -> cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("User-Agent: token-client/")
        .hasMessageContaining("expires_in=1000")
        .hasMessageContaining("access_token=Valid Access token")
        .hasMessageContaining("token_type=TOKEN TYPE")
        .hasMessageContaining("Server error while obtaining access token from XSUAA!")
        .hasMessageContaining("Http status code 500");
    Mockito.verify(restOperationsMock, times(3))
        .postForEntity(eq(TOKEN_KEYS_ENDPOINT_URI), any(), eq(Map.class));
  }

  @Test
  public void retrieveTokenKeys_interruptedExceptionDuringRetry_logsWarning()
      throws OAuth2ServiceException {
    mockResponse(responseBody, 500, 200);
    setConfigurationValues(1, Set.of(500));

    // Set up log capturing
    final Logger logger = (Logger) LoggerFactory.getLogger(XsuaaOAuth2TokenService.class);
    final ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);

    Thread.currentThread().interrupt(); // Simulate InterruptedException

    cut.requestAccessToken(TOKEN_KEYS_ENDPOINT_URI, headers, PARAMS);

    final List<ILoggingEvent> logsList = listAppender.list;
    assertThat(logsList).extracting(ILoggingEvent::getLevel).contains(Level.WARN);
    assertThat(logsList)
        .extracting(ILoggingEvent::getFormattedMessage)
        .contains("Thread.sleep has been interrupted. Retry starts now.");
    logger.detachAppender(listAppender);
    Mockito.verify(restOperationsMock, times(2))
        .postForEntity(eq(TOKEN_KEYS_ENDPOINT_URI), any(), eq(Map.class));
  }

  private void mockResponse(final Map<String, String> responseMap, final Integer... statusCodes) {
    final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
    headers.add("Content-Type", "application/json");
    final List<ResponseEntity<Map<String, String>>> responses =
        Arrays.stream(statusCodes)
            .map(
                statusCode ->
                    new ResponseEntity<>(responseMap, headers, HttpStatus.valueOf(statusCode)))
            .toList();
    final AtomicInteger index = new AtomicInteger(0);
    when(restOperationsMock.postForEntity(
            eq(TOKEN_KEYS_ENDPOINT_URI), any(HttpEntity.class), eq(Map.class)))
        .thenAnswer(
            invocation -> {
              final int currentIndex = index.getAndIncrement();
              return responses.get(currentIndex);
            });
  }

  private static void setConfigurationValues(
      final int maxRetryAttempts, final Set<Integer> retryStatusCodes) {
    final DefaultTokenClientConfiguration config = DefaultTokenClientConfiguration.getInstance();
    config.setRetryEnabled(true);
    config.setMaxRetryAttempts(maxRetryAttempts);
    config.setRetryStatusCodes(retryStatusCodes);
    config.setRetryDelayTime(0L);
  }

  private ArgumentMatcher<HttpEntity> httpEntityContainsMandatoryHeadersAndBody() {
    return (httpGet) -> {
      final boolean correctClientId = httpGet.getBody().toString().contains(CLIENT_ID);
      final boolean correctAppTid = httpGet.getBody().toString().contains(APP_TID);
      final boolean correctAzp = httpGet.getBody().toString().contains(AZP);
      final boolean correctCorrelationID =
          !httpGet.getHeaders().get(MDCHelper.CORRELATION_HEADER).get(0).isBlank();
      final boolean correctUserAgent =
          !httpGet
              .getHeaders()
              .get(org.springframework.http.HttpHeaders.USER_AGENT)
              .get(0)
              .isBlank();
      return correctAppTid
          && correctClientId
          && correctAzp
          && correctCorrelationID
          && correctUserAgent;
    };
  }
}
