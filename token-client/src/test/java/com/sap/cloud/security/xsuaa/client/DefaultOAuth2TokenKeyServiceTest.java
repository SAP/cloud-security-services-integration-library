package com.sap.cloud.security.xsuaa.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;

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
  private CloseableHttpClient httpClient;

  public DefaultOAuth2TokenKeyServiceTest() throws IOException {
    jsonWebKeysAsString =
        IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
  }

  @Before
  public void setUp() {
    httpClient = Mockito.mock(CloseableHttpClient.class);
    cut = new DefaultOAuth2TokenKeyService(httpClient);
  }

  @Test
  public void retrieveTokenKeys_httpClientIsNull_throwsException() {
    assertThatThrownBy(() -> new DefaultOAuth2TokenKeyService(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void retrieveTokenKeys_tokenEndpointUriIsNull_throwsException() {
    assertThatThrownBy(() -> cut.retrieveTokenKeys(null, PARAMS))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void retrieveTokenKeys_responseNotOk_throwsException() {
    mockResponse(ERROR_MESSAGE, HttpStatus.SC_BAD_REQUEST);

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Error retrieving token keys");
  }

  @Test
  public void retrieveTokenKeys_errorOccurs_throwsServiceException() throws IOException {
    when(httpClient.execute(any(), any(ResponseHandler.class)))
        .thenThrow(new IOException("IO Exception"));

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("IO Exception");
  }

  @Test
  public void retrieveTokenKeys_badResponse_throwsException() {
    mockResponse(ERROR_MESSAGE, 400);

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Request headers [")
        .hasMessageContaining("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
        .hasMessageContaining("x-client_id: client-id")
        .hasMessageContaining("x-azp: azp")
        .hasMessageContaining("Error retrieving token keys")
        .hasMessageContaining("Response Headers [testHeader: testValue]")
        .hasMessageContaining("Http status code 400");
  }

  @Test
  public void retrieveTokenKeys_errorOccursDuringRetry_throwsServiceException() throws IOException {
    mockResponse(ERROR_MESSAGE, 500, 400);
    final DefaultTokenClientConfiguration config = DefaultTokenClientConfiguration.getConfig();
    config.setRetryEnabled(true);
    config.setMaxRetryAttempts(1);

    assertThatThrownBy(() -> cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Request headers [")
        .hasMessageContaining("x-app_tid: 92768714-4c2e-4b79-bc1b-009a4127ee3c")
        .hasMessageContaining("x-client_id: client-id")
        .hasMessageContaining("x-azp: azp")
        .hasMessageContaining("Error retrieving token keys")
        .hasMessageContaining("Response Headers [testHeader: testValue]")
        .hasMessageContaining("Http status code 400");
    Mockito.verify(httpClient, times(2))
        .execute(any(HttpUriRequest.class), any(ResponseHandler.class));
  }

  @Test
  public void retrieveTokenKeys_withEmptyParams_executesSuccessfully() throws IOException {
    mockResponse(jsonWebKeysAsString, 200);

    final Map<String, String> emptyParams = Map.of();
    final String result = cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, emptyParams);

    assertThat(result).isNotEmpty();
    Mockito.verify(httpClient, times(1))
        .execute(any(HttpUriRequest.class), any(ResponseHandler.class));
  }

  @Test
  public void retrieveTokenKeys_executesCorrectHttpGetRequest() throws IOException {
    mockResponse(jsonWebKeysAsString, 200);

    cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

    Mockito.verify(httpClient, times(1))
        .execute(argThat(isCorrectHttpGetRequest()), any(ResponseHandler.class));
  }

  @Test
  public void retrieveTokenKeys_responseNotOk_retry_executesRetrySuccessfully() throws IOException {
    mockResponse(ERROR_MESSAGE, 500, 200);
    final DefaultTokenClientConfiguration config = DefaultTokenClientConfiguration.getConfig();
    config.setRetryEnabled(true);
    config.setMaxRetryAttempts(1);

    final String result = cut.retrieveTokenKeys(TOKEN_KEYS_ENDPOINT_URI, PARAMS);

    Mockito.verify(httpClient, times(2))
        .execute(any(HttpUriRequest.class), any(ResponseHandler.class));
    assertThat(result).isNotEmpty();
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
      when(httpClient.execute(any(), any(ResponseHandler.class)))
          .thenAnswer(
              invocation -> {
                final ResponseHandler responseHandler = invocation.getArgument(1);
                final CloseableHttpResponse response = responses.get(index.getAndIncrement());
                return responseHandler.handleResponse(response);
              });
    } catch (final IOException ignored) {
    }
  }

  private ArgumentMatcher<HttpUriRequest> isCorrectHttpGetRequest() {
    return (httpGet) -> {
      final boolean hasCorrectURI = httpGet.getURI().equals(TOKEN_KEYS_ENDPOINT_URI);
      final boolean correctMethod = httpGet.getMethod().equals(HttpMethod.GET.toString());
      final boolean correctTenantHeader =
          httpGet.getFirstHeader(HttpHeaders.X_APP_TID).getValue().equals(APP_TID);
      final boolean correctClientId =
          httpGet.getFirstHeader(HttpHeaders.X_CLIENT_ID).getValue().equals(CLIENT_ID);
      final boolean correctAzp = httpGet.getFirstHeader(HttpHeaders.X_AZP).getValue().equals(AZP);
      return hasCorrectURI && correctMethod && correctTenantHeader && correctClientId && correctAzp;
    };
  }
}
