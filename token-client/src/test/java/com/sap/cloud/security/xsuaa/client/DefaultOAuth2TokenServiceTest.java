/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.servlet.MDCHelper.CORRELATION_ID;
import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.servlet.MDCHelper;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

@RunWith(MockitoJUnitRunner.class)
public class DefaultOAuth2TokenServiceTest {

  private static final String ACCESS_TOKEN = "abc123";
  private static final String REFRESH_TOKEN = "def456";
  private static final String TOKEN_TYPE = "bearer";
  private static final String ERROR_MESSAGE = "Error message";
  private static final Map<String, String> PARAMS = Map.of("param1", "value1");
  private static final String VALID_JSON_RESPONSE =
      String.format(
          "{expires_in: 10000, access_token: %s, refresh_token: %s, token_type: %s}",
          ACCESS_TOKEN, REFRESH_TOKEN, TOKEN_TYPE);
  private static final URI TOKEN_URI =
      URI.create("https://subdomain.myauth.server.com/oauth/token");

  private CloseableHttpClient mockHttpClient;
  private DefaultOAuth2TokenService cut;

  @Before
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
        .hasMessageContaining("Error retrieving access token");
  }

  @Test
  public void requestAccessToken_errorOccurs_throwsServiceException() throws IOException {
    when(mockHttpClient.execute(any(), any(ResponseHandler.class)))
        .thenThrow(new IOException(ERROR_MESSAGE));

    assertThatThrownBy(() -> requestAccessToken(TOKEN_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
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
    verify(mockHttpClient, times(1)).execute(any(HttpPost.class), any(ResponseHandler.class));
  }

  @Test
  public void requestAccessToken_executesCorrectHttpPostRequest() throws IOException {
    mockResponse(VALID_JSON_RESPONSE, 200);

    requestAccessToken(TOKEN_URI, PARAMS);

    verify(mockHttpClient, times(1)).execute(any(HttpPost.class), any(ResponseHandler.class));
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

    verify(mockHttpClient, times(1)).execute(httpPostCaptor.capture(), any(ResponseHandler.class));
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
    final OAuth2ServiceException e =
        assertThrows(OAuth2ServiceException.class, () -> requestAccessToken(TOKEN_URI, emptyMap()));

    assertThat(e.getHeaders().get(0)).isEqualTo("testHeader: testValue");
    assertThat(e.getHttpStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED);
    assertThat(e.getMessage()).contains("Unauthorized!").contains(TOKEN_URI.toString());
  }

  @Test
  public void retrieveToken_testCache() throws IOException {
    mockResponse(VALID_JSON_RESPONSE, 200);
    cut.retrieveAccessTokenViaClientCredentialsGrant(
        TOKEN_URI, new ClientCredentials("myClientId", "mySecret"), null, null, emptyMap(), false);
    cut.retrieveAccessTokenViaClientCredentialsGrant(
        TOKEN_URI, new ClientCredentials("myClientId", "mySecret"), null, null, emptyMap(), false);

    verify(mockHttpClient, times(1)).execute(any(HttpPost.class), any(ResponseHandler.class));
  }

  @Test
  public void requestAccessToken_firstResponseNotOk_executesRetrySuccessfullyWithOKResponse()
      throws IOException {
    mockResponse(VALID_JSON_RESPONSE, 500, 200);
    setConfigurationValues(1, Set.of(500));

    final OAuth2TokenResponse result = requestAccessToken(TOKEN_URI, emptyMap());

    verify(mockHttpClient, times(2)).execute(any(HttpPost.class), any(ResponseHandler.class));
    assertThat(result.getAccessToken()).isEqualTo(ACCESS_TOKEN);
  }

  @Test
  public void requestAccessToken_allRetryableStatusCodes_executesRetrySuccessfullyWithBadResponse()
      throws IOException {
    mockResponse("Error", 408, 429, 500, 502, 503, 504, 400);
    setConfigurationValues(10, Set.of(408, 429, 500, 502, 503, 504));

    assertThatThrownBy(() -> requestAccessToken(TOKEN_URI, emptyMap()))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("Error")
        .hasMessageContaining("Http status code 400");
    verify(mockHttpClient, times(7)).execute(any(HttpPost.class), any(ResponseHandler.class));
  }

  @Test
  public void requestAccessToken_noRetryableStatusCodesSet_executesNoRetry() throws IOException {
    mockResponse("Error", 500);
    setConfigurationValues(10, Set.of());

    assertThatThrownBy(() -> requestAccessToken(TOKEN_URI, emptyMap()))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("Error")
        .hasMessageContaining("Http status code 500");
    verify(mockHttpClient, times(1)).execute(any(HttpPost.class), any(ResponseHandler.class));
  }

  @Test
  public void requestAccessToken_retryLogic_maxAttemptsReached_throwsException()
      throws IOException {
    mockResponse("Error", 500, 500, 500, 500);
    setConfigurationValues(2, Set.of(500));

    assertThatThrownBy(() -> requestAccessToken(TOKEN_URI, emptyMap()))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("Error");
    verify(mockHttpClient, times(3)).execute(any(HttpPost.class), any(ResponseHandler.class));
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
    verify(mockHttpClient, times(2)).execute(any(HttpPost.class), any(ResponseHandler.class));
  }

  private OAuth2TokenResponse requestAccessToken(
      final URI uri, final Map<String, String> optionalParameters) throws OAuth2ServiceException {
    final HttpHeaders withoutAuthorizationHeader =
        HttpHeadersFactory.createWithoutAuthorizationHeader();
    return cut.requestAccessToken(uri, withoutAuthorizationHeader, optionalParameters);
  }

  private void mockResponse(final String responseAsString, final Integer... statusCodes) {
    final List<CloseableHttpResponse> responses =
        Arrays.stream(statusCodes)
            .map(
                statusCode ->
                    HttpClientTestFactory.createHttpResponse(responseAsString, statusCode))
            .toList();

    final AtomicInteger index = new AtomicInteger(0);
    try {
      when(mockHttpClient.execute(any(HttpPost.class), any(ResponseHandler.class)))
          .thenAnswer(
              invocation -> {
                final ResponseHandler responseHandler = invocation.getArgument(1);
                final CloseableHttpResponse response = responses.get(index.getAndIncrement());
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
