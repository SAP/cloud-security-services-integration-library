package com.sap.cloud.security.xsuaa.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.client.SpringTokenClientConfiguration;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
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
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestOperations;

public class SpringOAuth2TokenKeyServiceTest {

  public static final URI TOKEN_KEYS_ENDPOINT_URI =
      URI.create("https://token.endpoint.io/token_keys");
  public static final String APP_TID = "92768714-4c2e-4b79-bc1b-009a4127ee3c";
  public static final String CLIENT_ID = "client-id";
  public static final String AZP = "azp";
  public static final String ERROR_MESSAGE = "useful error message";
  private static final Map<String, String> PARAMS =
      Map.of(
          HttpHeaders.X_APP_TID, APP_TID,
          HttpHeaders.X_CLIENT_ID, CLIENT_ID,
          HttpHeaders.X_AZP, AZP);
  private final String jsonWebKeysAsString;
  private RestOperations restOperationsMock;
  private SpringOAuth2TokenKeyService cut;

  public SpringOAuth2TokenKeyServiceTest() throws IOException {
    jsonWebKeysAsString =
        IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
  }

  @BeforeEach
  public void setUp() {
    restOperationsMock = Mockito.mock(RestOperations.class);
    cut = new SpringOAuth2TokenKeyService(restOperationsMock);
  }

  @Test
  public void retrieveTokenKeys_responseNotOk_throwsException() {
    mockResponse(ERROR_MESSAGE, 500);
    setConfigurationValues(0, Set.of());

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Error retrieving token keys");
  }

  @Test
  public void retrieveTokenKeys_httpStatusCodeExceptionOccurs_throwsServiceException() {
    when(restOperationsMock.exchange(
            eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(HttpEntity.class), eq(String.class)))
        .thenThrow(new HttpStatusCodeException(HttpStatus.BAD_REQUEST) {});

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("Error retrieving token keys")
        .hasMessageContaining("Http status code 400");
  }

  @Test
  public void retrieveTokenKeys_errorOccurs_throwsServiceException() {
    when(restOperationsMock.exchange(
            eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(HttpEntity.class), eq(String.class)))
        .thenThrow(new RuntimeException("IO Exception"));

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("IO Exception");
  }

  @Test
  public void retrieveTokenKeys_restOperationsIsNull_throwsException() {
    assertThatThrownBy(() -> new SpringOAuth2TokenKeyService(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void retrieveTokenKeys_tokenEndpointUriIsNull_throwsException() {
    assertThatThrownBy(() -> cut.retrieveTokenKeys(null, PARAMS))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void retrieveTokenKeys_badResponse_throwsException() {
    mockResponse(ERROR_MESSAGE, 400);

    final OAuth2ServiceException e =
        assertThrows(
            OAuth2ServiceException.class,
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
  public void retrieveTokenKeys_errorOccursDuringRetry_throwsServiceException() {
    mockResponse(ERROR_MESSAGE, 500, 400);
    setConfigurationValues(10, Set.of(500));

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(
            "Request headers [Accept: application/json, User-Agent: token-client/")
        .hasMessageContaining("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
        .hasMessageContaining("x-client_id: client-id")
        .hasMessageContaining("x-azp: azp")
        .hasMessageContaining("Error retrieving token keys")
        .hasMessageContaining("Response Headers ")
        .hasMessageContaining("Http status code 400");
    Mockito.verify(restOperationsMock, times(2))
        .exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(), eq(String.class));
  }

  @Test
  public void retrieveTokenKeys_executesCorrectHttpGetRequest() throws OAuth2ServiceException {
    mockResponse(jsonWebKeysAsString, 200);

    cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

    Mockito.verify(restOperationsMock, times(1))
        .exchange(
            eq(TOKEN_KEYS_ENDPOINT_URI),
            eq(GET),
            argThat(httpEntityContainsMandatoryHeaders()),
            eq(String.class));
  }

  @Test
  public void retrieveTokenKeys_withEmptyParams_executesSuccessfully()
      throws OAuth2ServiceException {
    mockResponse(jsonWebKeysAsString, 200);

    final Map<String, String> emptyParams = Map.of();
    final String result = cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, emptyParams);

    assertThat(result).isNotEmpty();
    Mockito.verify(restOperationsMock, times(1))
        .exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(HttpEntity.class), eq(String.class));
  }

  @Test
  public void retrieveTokenKeys_responseNotOk_retry_executesRetrySuccessfully() throws IOException {
    mockResponse(ERROR_MESSAGE, 500, 200);
    setConfigurationValues(1, Set.of(500));

    final String result = cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

    Mockito.verify(restOperationsMock, times(2))
        .exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(), eq(String.class));
    assertThat(result).isNotEmpty();
  }

  @Test
  public void retrieveTokenKeys_allRetryableStatusCodes_executesRetrySuccessfullyWithBadResponse() {
    mockResponse(ERROR_MESSAGE, 408, 429, 500, 502, 503, 504, 400);
    setConfigurationValues(10, Set.of(408, 429, 500, 502, 503, 504));

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(
            "Request headers [Accept: application/json, User-Agent: token-client/")
        .hasMessageContaining("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
        .hasMessageContaining("x-client_id: client-id")
        .hasMessageContaining("x-azp: azp")
        .hasMessageContaining("Error retrieving token keys")
        .hasMessageContaining("Response Headers ")
        .hasMessageContaining("Http status code 400");
    Mockito.verify(restOperationsMock, times(7))
        .exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(), eq(String.class));
  }

  @Test
  public void retrieveTokenKeys_noRetryableStatusCodesSet_executesNoRetry() {
    mockResponse(ERROR_MESSAGE, 500);
    setConfigurationValues(10, Set.of());

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(
            "Request headers [Accept: application/json, User-Agent: token-client/")
        .hasMessageContaining("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
        .hasMessageContaining("x-client_id: client-id")
        .hasMessageContaining("x-azp: azp")
        .hasMessageContaining("Error retrieving token keys")
        .hasMessageContaining("Response Headers ")
        .hasMessageContaining("Http status code 500");
    Mockito.verify(restOperationsMock, times(1))
        .exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(), eq(String.class));
  }

  @Test
  public void retrieveTokenKeys_retryLogic_maxAttemptsReached_throwsException() {
    mockResponse(ERROR_MESSAGE, 500, 500, 500, 500);
    setConfigurationValues(2, Set.of(500));

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Error retrieving token keys");
    Mockito.verify(restOperationsMock, times(3))
        .exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(), eq(String.class));
  }

  @Test
  public void retrieveTokenKeys_interruptedExceptionDuringRetry_logsWarning()
      throws OAuth2ServiceException {
    mockResponse(ERROR_MESSAGE, 500, 200);
    setConfigurationValues(1, Set.of(500));

    // Set up log capturing
    final Logger logger = (Logger) LoggerFactory.getLogger(SpringOAuth2TokenKeyService.class);
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
    Mockito.verify(restOperationsMock, times(2))
        .exchange(eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(), eq(String.class));
  }

  private void mockResponse(final String responseAsString, final Integer... statusCodes) {
    final MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
    headers.add("Content-Type", "application/json");
    final List<ResponseEntity<String>> responses =
        Arrays.stream(statusCodes)
            .map(statusCode -> new ResponseEntity<>(responseAsString, headers, statusCode))
            .toList();
    final AtomicInteger index = new AtomicInteger(0);
    when(restOperationsMock.exchange(
            eq(TOKEN_KEYS_ENDPOINT_URI), eq(GET), any(HttpEntity.class), eq(String.class)))
        .thenAnswer(
            invocation -> {
              final int currentIndex = index.getAndIncrement();
              return responses.get(currentIndex);
            });
  }

  private static void setConfigurationValues(
      final int maxRetryAttempts, final Set<Integer> retryStatusCodes) {
    final SpringTokenClientConfiguration config = SpringTokenClientConfiguration.getInstance();
    config.setRetryEnabled(true);
    config.setMaxRetryAttempts(maxRetryAttempts);
    config.setRetryStatusCodes(retryStatusCodes);
    config.setRetryDelayTime(0L);
  }

  private ArgumentMatcher<HttpEntity> httpEntityContainsMandatoryHeaders() {
    return (httpGet) -> {
      final boolean correctClientId =
          httpGet.getHeaders().get(HttpHeaders.X_CLIENT_ID).get(0).equals(CLIENT_ID);
      final boolean correctAppTid =
          httpGet.getHeaders().get(HttpHeaders.X_APP_TID).get(0).equals(APP_TID);
      final boolean correctAzp = httpGet.getHeaders().get(HttpHeaders.X_AZP).get(0).equals(AZP);
      return correctAppTid && correctClientId && correctAzp;
    };
  }
}
