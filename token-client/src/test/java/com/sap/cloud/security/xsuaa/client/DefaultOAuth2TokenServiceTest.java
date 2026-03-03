/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.servlet.MDCHelper.CORRELATION_ID;
import org.junit.jupiter.api.Test;
import static java.util.Collections.emptyMap;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.*;
import org.junit.jupiter.api.Test;

import ch.qos.logback.classic.Level;
import org.junit.jupiter.api.Test;
import ch.qos.logback.classic.Logger;
import org.junit.jupiter.api.Test;
import ch.qos.logback.classic.spi.ILoggingEvent;
import org.junit.jupiter.api.Test;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.Test;
import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import org.junit.jupiter.api.Test;
import com.sap.cloud.security.config.ClientCredentials;
import org.junit.jupiter.api.Test;
import com.sap.cloud.security.servlet.MDCHelper;
import org.junit.jupiter.api.Test;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.junit.jupiter.api.Test;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import org.junit.jupiter.api.Test;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import java.net.URI;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import java.util.List;
import org.junit.jupiter.api.Test;
import java.util.Map;
import org.junit.jupiter.api.Test;
import java.util.Set;
import org.junit.jupiter.api.Test;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.apache.hc.core5.http.HttpEntity;
import org.junit.jupiter.api.Test;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.junit.jupiter.api.Test;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.junit.jupiter.api.Test;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.junit.jupiter.api.Test;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.Test;
import org.assertj.core.util.Maps;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.junit.jupiter.api.Test;

public class DefaultOAuth2TokenServiceTest {

  private static final String ACCESS_TOKEN = "abc123";
  private static final String REFRESH_TOKEN = "def456";
  private static final String TOKEN_TYPE = "bearer";
  private static final String ERROR_MESSAGE = "Error message";
  private static final Map<String, String> PARAMS = Map.of("param1", "value1");
  private static final String VALID_JSON_RESPONSE =
			"{expires_in: 10000, access_token: %s, refresh_token: %s, token_type: %s}".formatted(
					ACCESS_TOKEN, REFRESH_TOKEN, TOKEN_TYPE);
  private static final URI TOKEN_URI =
      URI.create("https://subdomain.myauth.server.com/oauth/token");

  private CloseableHttpClient mockHttpClient;
  private DefaultOAuth2TokenService cut;

  @BeforeEach
  public void setup() {
    mockHttpClient = Mockito.mock(CloseableHttpClient.class);
    cut = new DefaultOAuth2TokenService(mockHttpClient);
  }

  @Test
  public void requestAccessToken_httpClientIsNull_throwsException() {
    assertThatThrownBy(() -> new DefaultOAuth2TokenService(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void requestAccessToken_tokenEndpointUriIsNull_throwsException() {
    assertThatThrownBy(() -> requestAccessToken(null, emptyMap()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void requestAccessToken_responseNotOk_throwsException() {
    mockResponse(ERROR_MESSAGE, HttpStatus.SC_BAD_REQUEST);

    assertThatThrownBy(() -> requestAccessToken(TOKEN_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining(TOKEN_URI.toString())
        .hasMessageContaining("Error requesting access token!");
  }

  @Test
  public void requestAccessToken_errorOccurs_throwsServiceException() throws IOException {
    when(mockHttpClient.execute(any(), any(HttpClientResponseHandler.class)))
        .thenThrow(new IOException(ERROR_MESSAGE));

    assertThatThrownBy(() -> requestAccessToken(TOKEN_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(TOKEN_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageNotContaining("Response Headers [")
        .extracting(OAuth2ServiceException.class::cast)
        .extracting(OAuth2ServiceException::getHttpStatusCode)
        .isEqualTo(0);
  }

  @Test
  public void requestAccessToken_emptyResponse_throwsException() {
    mockResponse("{}", 200);

    assertThatThrownBy(() -> requestAccessToken(TOKEN_URI, emptyMap()))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("expires_in");
  }

  @Test
  public void requestAccessToken_withEmptyParams_executesSuccessfully() throws IOException {
    mockResponse(VALID_JSON_RESPONSE, 200);

    final Map<String, String> emptyParams = Map.of();
    final OAuth2TokenResponse result = requestAccessToken(TOKEN_URI, emptyParams);

    assertThat(result).isNotNull();
    verify(mockHttpClient, times(1)).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
  }

  @Test
  public void requestAccessToken_executesCorrectHttpPostRequest() throws IOException {
    mockResponse(VALID_JSON_RESPONSE, 200);

    requestAccessToken(TOKEN_URI, PARAMS);

    verify(mockHttpClient, times(1)).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
  }

  @Test
  public void requestAccessToken_yieldsTokenResponseWithCorrectData() throws IOException {
    mockResponse(VALID_JSON_RESPONSE, 200);

    final OAuth2TokenResponse re = requestAccessToken(TOKEN_URI, emptyMap());

    assertThat(re.getAccessToken()).isEqualTo(ACCESS_TOKEN);
    assertThat(re.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
    assertThat(re.getExpiredAt()).isAfter(Instant.now());
    assertThat(re.getTokenType()).isEqualTo(TOKEN_TYPE);
  }

  @Test
  public void requestAccessToken_correlationIdProvisioning() throws IOException {
    mockResponse(VALID_JSON_RESPONSE, 200, 200);

    final ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    final Logger logger = (Logger) LoggerFactory.getLogger(MDCHelper.class);
    logger.setLevel(Level.DEBUG);
    listAppender.start();
    logger.addAppender(listAppender);

    requestAccessToken(TOKEN_URI, emptyMap());
    assertThat(listAppender.list.get(0).getLevel()).isEqualTo(Level.INFO);
    assertThat(listAppender.list.get(0).getMessage()).contains("was not found in the MDC");

    MDC.put(CORRELATION_ID, "my-correlation-id");
    requestAccessToken(TOKEN_URI, emptyMap());
    assertThat(listAppender.list.get(1).getLevel()).isEqualTo(Level.DEBUG);
    assertThat(listAppender.list.get(1).getArgumentArray()[1]).isEqualTo(("my-correlation-id"));
    MDC.clear();
  }

  @Test
  public void requestAccessToken_executeWithAdditionalParameters_putsParametersIntoPostBody()
      throws IOException {
    mockResponse(VALID_JSON_RESPONSE, 200);
    final ArgumentCaptor<HttpPost> httpPostCaptor = ArgumentCaptor.forClass(HttpPost.class);
    requestAccessToken(TOKEN_URI, Maps.newHashMap("myKey", "myValue"));

    verify(mockHttpClient, times(1)).execute(httpPostCaptor.capture(), any(HttpClientResponseHandler.class));
    final HttpPost httpPost = httpPostCaptor.getValue();
    final HttpEntity httpEntity = httpPost.getEntity();
    assertThat(httpEntity).isNotNull();
    final String postBody = IOUtils.toString(httpEntity.getContent(), StandardCharsets.UTF_8);
    assertThat(postBody).contains("myKey=myValue");
  }

  @Test
  public void
      requestAccessToken_httpResponseWithErrorStatusCode_throwsExceptionContainingMessage() {
    mockResponse("Unauthorized!", 401);

    assertThatThrownBy(() -> requestAccessToken(TOKEN_URI, emptyMap()))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("Unauthorized!")
        .hasMessageContaining(TOKEN_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .extracting(OAuth2ServiceException.class::cast)
        .extracting(OAuth2ServiceException::getHttpStatusCode)
        .isEqualTo(HttpStatus.SC_UNAUTHORIZED);
  }

  @Test
  public void retrieveToken_testCache() throws IOException {
    mockResponse(VALID_JSON_RESPONSE, 200);
    cut.retrieveAccessTokenViaClientCredentialsGrant(
        TOKEN_URI, new ClientCredentials("myClientId", "mySecret"), null, null, emptyMap(), false);
    cut.retrieveAccessTokenViaClientCredentialsGrant(
        TOKEN_URI, new ClientCredentials("myClientId", "mySecret"), null, null, emptyMap(), false);

    verify(mockHttpClient, times(1)).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
  }

  @Test
  public void requestAccessToken_firstResponseNotOk_executesRetrySuccessfullyWithOKResponse()
      throws IOException {
    mockResponse(VALID_JSON_RESPONSE, 500, 200);
    setConfigurationValues(1, Set.of(500));

    final OAuth2TokenResponse result = requestAccessToken(TOKEN_URI, emptyMap());

    verify(mockHttpClient, times(2)).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
    assertThat(result.getAccessToken()).isEqualTo(ACCESS_TOKEN);
  }

  @Test
  public void requestAccessToken_allRetryableStatusCodes_executesRetrySuccessfullyWithBadResponse()
      throws IOException {
    mockResponse(ERROR_MESSAGE, 408, 429, 500, 502, 503, 504, 400);
    setConfigurationValues(10, Set.of(408, 429, 500, 502, 503, 504));

    assertThatThrownBy(() -> requestAccessToken(TOKEN_URI, emptyMap()))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(TOKEN_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("Http status code 400");
    verify(mockHttpClient, times(7)).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
  }

  @Test
  public void requestAccessToken_noRetryableStatusCodesSet_executesNoRetry() throws IOException {
    mockResponse(ERROR_MESSAGE, 500);
    setConfigurationValues(10, Set.of());

    assertThatThrownBy(() -> requestAccessToken(TOKEN_URI, emptyMap()))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(TOKEN_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("Http status code 500");
    verify(mockHttpClient, times(1)).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
  }

  @Test
  public void requestAccessToken_retryLogic_maxAttemptsReached_throwsException()
      throws IOException {
    mockResponse(ERROR_MESSAGE, 500, 500, 500, 500);
    setConfigurationValues(2, Set.of(500));

    assertThatThrownBy(() -> requestAccessToken(TOKEN_URI, emptyMap()))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining(TOKEN_URI.toString());
    verify(mockHttpClient, times(3)).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
  }

  @Test
  public void requestAccessToken_interruptedExceptionDuringRetry_logsWarning() throws IOException {
    mockResponse(VALID_JSON_RESPONSE, 500, 200);
    setConfigurationValues(1, Set.of(500));

    // Set up log capturing
    final Logger logger = (Logger) LoggerFactory.getLogger(DefaultOAuth2TokenService.class);
    final ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);

    Thread.currentThread().interrupt(); // Simulate InterruptedException

    requestAccessToken(TOKEN_URI, emptyMap());

    final List<ILoggingEvent> logsList = listAppender.list;
    assertThat(logsList).extracting(ILoggingEvent::getLevel).contains(Level.WARN);
    assertThat(logsList)
        .extracting(ILoggingEvent::getFormattedMessage)
        .contains("Thread.sleep has been interrupted. Retry starts now.");
    logger.detachAppender(listAppender);
    verify(mockHttpClient, times(2)).execute(any(HttpPost.class), any(HttpClientResponseHandler.class));
  }

  private OAuth2TokenResponse requestAccessToken(
      final URI uri, final Map<String, String> optionalParameters) throws OAuth2ServiceException {
    final HttpHeaders withoutAuthorizationHeader =
        HttpHeadersFactory.createWithoutAuthorizationHeader();
    return cut.requestAccessToken(uri, withoutAuthorizationHeader, optionalParameters);
  }

  private void mockResponse(final String responseAsString, final Integer... statusCodes) {
    final List<ClassicHttpResponse> responses =
        Arrays.stream(statusCodes)
            .map(
                statusCode ->
                    HttpClientTestFactory.createHttpResponse(responseAsString, statusCode))
            .toList();

    final AtomicInteger index = new AtomicInteger(0);
    try {
      when(mockHttpClient.execute(any(HttpPost.class), any(HttpClientResponseHandler.class)))
          .thenAnswer(
              invocation -> {
                final HttpClientResponseHandler<String> responseHandler = invocation.getArgument(1);
                final ClassicHttpResponse response = responses.get(index.getAndIncrement());
                return responseHandler.handleResponse(response);
              });
    } catch (final IOException ignored) {
    }
  }

  private static void setConfigurationValues(
      final int maxRetryAttempts, final Set<Integer> retryStatusCodes) {
    final DefaultTokenClientConfiguration config = DefaultTokenClientConfiguration.getInstance();
    config.setRetryEnabled(true);
    config.setMaxRetryAttempts(maxRetryAttempts);
    config.setRetryStatusCodes(retryStatusCodes);
    config.setRetryDelayTime(0L);
  }
}
