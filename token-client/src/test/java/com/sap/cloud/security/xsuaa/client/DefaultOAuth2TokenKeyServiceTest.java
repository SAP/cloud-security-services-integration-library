package com.sap.cloud.security.xsuaa.client;
import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;

import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_OSB_PLAN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;

public class DefaultOAuth2TokenKeyServiceTest {

  private static final URI TOKEN_KEYS_ENDPOINT_URI = URI.create("https://tokenKeys.io/token_keys");
  private static final String APP_TID = "92768714-4c2e-4b79-bc1b-009a4127ee3c";
  private static final String CLIENT_ID = "client-id";
  private static final String AZP = "azp";
  private static final String ERROR_MESSAGE = "Error message";
  private static final Map<String, String> PARAMS =
      Map.of(
          HttpHeaders.X_APP_TID,
          APP_TID,
          HttpHeaders.X_CLIENT_ID,
          CLIENT_ID,
          HttpHeaders.X_AZP,
          AZP);
  private final String jsonWebKeysAsString;
  private DefaultOAuth2TokenKeyService cut;
  private SecurityHttpClient httpClient;

  public DefaultOAuth2TokenKeyServiceTest() throws IOException {
    jsonWebKeysAsString =
        IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
  }

  @BeforeEach
  public void setUp() {
    httpClient = Mockito.mock(SecurityHttpClient.class);
    cut = new DefaultOAuth2TokenKeyService(httpClient);
  }

  @Test
  public void retrieveTokenKeys_httpClientIsNull_throwsException() {
    assertThatThrownBy(() -> new DefaultOAuth2TokenKeyService((SecurityHttpClient) null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void retrieveTokenKeys_tokenEndpointUriIsNull_throwsException() {
    assertThatThrownBy(() -> cut.retrieveTokenKeys(null, PARAMS))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void retrieveTokenKeys_errorOccurs_throwsServiceException() throws IOException {
    when(httpClient.execute(any(SecurityHttpRequest.class)))
        .thenThrow(new IOException(ERROR_MESSAGE));

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Request Headers [")
        .hasMessageNotContaining("Response Headers [")
        .extracting(OAuth2ServiceException.class::cast)
        .extracting(OAuth2ServiceException::getHttpStatusCode)
        .isEqualTo(0);
  }

  @Test
  public void retrieveTokenKeys_badResponse_throwsException() {
    mockResponse(ERROR_MESSAGE, 400);

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
        .hasMessageContaining("x-client_id: client-id")
        .hasMessageContaining("x-azp: azp")
        .hasMessageContaining("Error retrieving token keys")
        .hasMessageContaining("Http status code 400");
  }

  @Test
  public void retrieveTokenKeys_errorOccursDuringRetry_throwsServiceException() throws IOException {
    mockResponse(ERROR_MESSAGE, 500, 400);
    setConfigurationValues(1, Set.of(500));

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
        .hasMessageContaining("x-client_id: client-id")
        .hasMessageContaining("x-azp: azp")
        .hasMessageContaining("Error retrieving token keys")
        .hasMessageContaining("Http status code 400");
    Mockito.verify(httpClient, times(2))
        .execute(any(SecurityHttpRequest.class));
  }

  @Test
  public void retrieveTokenKeys_withEmptyParams_executesSuccessfully() throws IOException {
    mockResponse(jsonWebKeysAsString, 200);

    final Map<String, String> emptyParams = Map.of();
    final String result = cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, emptyParams);

    assertThat(result).isNotEmpty();
    Mockito.verify(httpClient, times(1))
        .execute(any(SecurityHttpRequest.class));
  }

  @Test
  public void retrieveTokenKeys_executesCorrectHttpGetRequest() throws IOException {
    mockResponse(jsonWebKeysAsString, 200);

    cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

    Mockito.verify(httpClient, times(1))
        .execute(argThat(isCorrectHttpGetRequest()));
  }

  @Test
  public void retrieveTokenKeys_firstResponseNotOk_executesRetrySuccessfullyWithOKResponse()
      throws IOException {
    mockResponse(ERROR_MESSAGE, 500, 200);
    setConfigurationValues(1, Set.of(500));

    final String result = cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

    Mockito.verify(httpClient, times(2))
        .execute(any(SecurityHttpRequest.class));
    assertThat(result).isNotEmpty();
  }

  @Test
  public void retrieveTokenKeys_allRetryableStatusCodes_executesRetrySuccessfullyWithBadResponse()
      throws IOException {
    mockResponse(ERROR_MESSAGE, 408, 429, 500, 502, 503, 504, 400);
    setConfigurationValues(10, Set.of(408, 429, 500, 502, 503, 504));

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
        .hasMessageContaining("x-client_id: client-id")
        .hasMessageContaining("x-azp: azp")
        .hasMessageContaining("Error retrieving token keys")
        .hasMessageContaining("Http status code 400");
    Mockito.verify(httpClient, times(7))
        .execute(any(SecurityHttpRequest.class));
  }

  @Test
  public void retrieveTokenKeys_noRetryableStatusCodesSet_executesNoRetry() throws IOException {
    mockResponse(ERROR_MESSAGE, 500);
    setConfigurationValues(10, Set.of());

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
        .hasMessageContaining("x-client_id: client-id")
        .hasMessageContaining("x-azp: azp")
        .hasMessageContaining("Error retrieving token keys")
        .hasMessageContaining("Http status code 500");
    Mockito.verify(httpClient, times(1))
        .execute(any(SecurityHttpRequest.class));
  }

  @Test
  public void retrieveTokenKeys_retryLogic_maxAttemptsReached_throwsException() throws IOException {
    mockResponse(ERROR_MESSAGE, 500, 500, 500, 500);
    setConfigurationValues(2, Set.of(500));

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(TOKEN_KEYS_ENDPOINT_URI.toString())
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("Error retrieving token keys");
    Mockito.verify(httpClient, times(3))
        .execute(any(SecurityHttpRequest.class));
  }

  @Test
  public void retrieveTokenKeys_interruptedExceptionDuringRetry_logsWarning() throws IOException {
    mockResponse(ERROR_MESSAGE, 500, 200);
    setConfigurationValues(1, Set.of(500));

    // Set up log capturing
    final Logger logger = (Logger) LoggerFactory.getLogger(DefaultOAuth2TokenKeyService.class);
    final ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);

    Thread.currentThread().interrupt(); // Simulate InterruptedException

    cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

    final List<ILoggingEvent> logsList = listAppender.list;
    assertThat(logsList).extracting(ILoggingEvent::getLevel).contains(Level.WARN);
    assertThat(logsList)
        .extracting(ILoggingEvent::getFormattedMessage)
        .contains("Thread.sleep has been interrupted. Retry starts now.");
    logger.detachAppender(listAppender);
    Mockito.verify(httpClient, times(2))
        .execute(any(SecurityHttpRequest.class));
  }

  @Test
  public void retrieveTokenKeys_successfulResponse_setsServicePlan() throws IOException {
    Map<String, String> headers = new java.util.HashMap<>();
    headers.put(X_OSB_PLAN, "test-plan");
    final SecurityHttpResponse response =
        HttpClientTestFactory.createHttpResponse(jsonWebKeysAsString, 200, headers);

    try (final MockedStatic<SecurityContext> mockedSecurityContext =
        mockStatic(SecurityContext.class)) {
      when(httpClient.execute(any(SecurityHttpRequest.class)))
          .thenAnswer(
              invocation -> {
                // Response handler no longer needed
                return response;
              });

      cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

      mockedSecurityContext.verify(() -> SecurityContext.setServicePlans("test-plan"), times(1));
    }
  }

  private void mockResponse(final String responseAsString, final Integer... statusCodes) {
    final List<SecurityHttpResponse> responses =
        Arrays.stream(statusCodes)
            .map(
                statusCode ->
                    HttpClientTestFactory.createHttpResponse(responseAsString, statusCode))
            .toList();

    final AtomicInteger index = new AtomicInteger(0);
    try {
      when(httpClient.execute(any(SecurityHttpRequest.class)))
          .thenAnswer(
              invocation -> {
                // Response handler no longer needed
                final SecurityHttpResponse response = responses.get(index.getAndIncrement());
                return response;
              });
    } catch (final IOException ignored) {
    }
  }

  private void setConfigurationValues(
      final int maxRetryAttempts, final Set<Integer> retryStatusCodes) {
    final DefaultTokenClientConfiguration config = DefaultTokenClientConfiguration.getInstance();
    config.setRetryEnabled(true);
    config.setMaxRetryAttempts(maxRetryAttempts);
    config.setRetryStatusCodes(retryStatusCodes);
    config.setRetryDelayTime(0L);
  }

  private ArgumentMatcher<SecurityHttpRequest> isCorrectHttpGetRequest() {
    return (request) -> {
      try {
        final boolean hasCorrectURI = request.getUri().equals(TOKEN_KEYS_ENDPOINT_URI);
        final boolean correctMethod = request.getMethod().equals("GET");
        final boolean correctTenantHeader =
            request.getHeaders().get(HttpHeaders.X_APP_TID).equals(APP_TID);
        final boolean correctClientId =
            request.getHeaders().get(HttpHeaders.X_CLIENT_ID).equals(CLIENT_ID);
        final boolean correctAzp = request.getHeaders().get(HttpHeaders.X_AZP).equals(AZP);
        return hasCorrectURI && correctMethod && correctTenantHeader && correctClientId && correctAzp;
      } catch (Exception e) {
        return false;
      }
    };
  }
}
