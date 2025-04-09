/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.client.OidcConfigurationService.DISCOVERY_ENDPOINT_DEFAULT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.client.SpringTokenClientConfiguration;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

public class SpringOidcConfigurationServiceTest {
  public static final URI CONFIG_ENDPOINT_URI =
      URI.create("https://sub.myauth.com" + DISCOVERY_ENDPOINT_DEFAULT);
  private static final String ERROR_MESSAGE = "Error message";
  private RestOperations restOperationsMock;
  private SpringOidcConfigurationService cut;

  private final String jsonOidcConfiguration;

  public SpringOidcConfigurationServiceTest() throws IOException {
    jsonOidcConfiguration =
        IOUtils.resourceToString("/oidcConfiguration.json", StandardCharsets.UTF_8);
  }

  @Before
  public void setUp() throws Exception {
    restOperationsMock = mock(RestOperations.class);
    cut = new SpringOidcConfigurationService(restOperationsMock);
  }

  @Test
  public void retrieveEndpoints_restOperationsIsNull_throwsException() {
    assertThatThrownBy(() -> new SpringOidcConfigurationService(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void retrieveEndpoints_parameterIsNull_throwsException() {
    assertThatThrownBy(() -> retrieveEndpoints(null)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void retrieveEndpoints_badRequest_throwsException() {
    mockResponse(ERROR_MESSAGE, 400);

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(CONFIG_ENDPOINT_URI.toString())
        .hasMessageContaining("Http status code 400")
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("Error retrieving configured oidc endpoints");
  }

  @Test
  public void retrieveEndpoints_executesHttpGetRequestWithCorrectURI()
      throws OAuth2ServiceException {
    mockResponse();

    retrieveEndpoints();

    Mockito.verify(restOperationsMock, times(1))
        .exchange(eq(CONFIG_ENDPOINT_URI), eq(HttpMethod.GET), any(), eq(String.class));
  }

  @Test
  public void retrieveEndpoints_httpClientErrorOccurs_throwsServiceException() {
    when(restOperationsMock.exchange(
            eq(CONFIG_ENDPOINT_URI), eq(HttpMethod.GET), any(), eq(String.class)))
        .thenThrow(new HttpClientErrorException(HttpStatus.INTERNAL_SERVER_ERROR));

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining("Request Headers [")
        .hasMessageNotContaining("Response Headers [")
        .extracting(OAuth2ServiceException.class::cast)
        .extracting(OAuth2ServiceException::getHttpStatusCode)
        .isEqualTo(500);
  }

  @Test
  public void retrieveTokenKeys_errorOccursDuringRetry_throwsServiceException() {
    mockResponse(ERROR_MESSAGE, 500, 400);
    setConfigurationValues(1, Set.of(500));

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(CONFIG_ENDPOINT_URI.toString())
        .hasMessageContaining("Http status code 400")
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("Error retrieving configured oidc endpoints");
    Mockito.verify(restOperationsMock, times(2))
        .exchange(eq(CONFIG_ENDPOINT_URI), eq(HttpMethod.GET), any(), eq(String.class));
  }

  @Test
  public void retrieveEndpoints_containsBothKeys() throws OAuth2ServiceException {
    mockResponse();

    final OAuth2ServiceEndpointsProvider result = retrieveEndpoints();

    assertThat(result.getTokenEndpoint()).hasToString("http://localhost/oauth/token");
    assertThat(result.getJwksUri()).hasToString("http://localhost/token_keys");
    assertThat(result.getAuthorizeEndpoint()).hasToString("http://localhost/oauth/authorize");
  }

  @Test
  public void retrieveTokenKeys_firstResponseNotOk_executesRetrySuccessfullyWithOKResponse()
      throws OAuth2ServiceException {
    mockResponse(jsonOidcConfiguration, 500, 200);
    setConfigurationValues(1, Set.of(500));

    final OAuth2ServiceEndpointsProvider result = retrieveEndpoints();

    Mockito.verify(restOperationsMock, times(2))
        .exchange(eq(CONFIG_ENDPOINT_URI), eq(HttpMethod.GET), any(), eq(String.class));
    assertThat(result).isNotNull();
  }

  @Test
  public void retrieveTokenKeys_allRetryableStatusCodes_executesRetrySuccessfullyWithBadResponse() {
    mockResponse(ERROR_MESSAGE, 408, 429, 500, 502, 503, 504, 400);
    setConfigurationValues(10, Set.of(408, 429, 500, 502, 503, 504));

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(CONFIG_ENDPOINT_URI.toString())
        .hasMessageContaining("Error retrieving configured oidc endpoints")
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("Http status code 400");
    Mockito.verify(restOperationsMock, times(7))
        .exchange(eq(CONFIG_ENDPOINT_URI), eq(HttpMethod.GET), any(), eq(String.class));
  }

  @Test
  public void retrieveTokenKeys_noRetryableStatusCodesSet_executesNoRetry() {
    mockResponse(ERROR_MESSAGE, 500);
    setConfigurationValues(10, Set.of());

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(CONFIG_ENDPOINT_URI.toString())
        .hasMessageContaining("Error retrieving configured oidc endpoints")
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("Http status code 500");
    Mockito.verify(restOperationsMock, times(1))
        .exchange(eq(CONFIG_ENDPOINT_URI), eq(HttpMethod.GET), any(), eq(String.class));
  }

  @Test
  public void retrieveTokenKeys_retryLogic_maxAttemptsReached_throwsException() {
    mockResponse(ERROR_MESSAGE, 500, 500, 500, 500);
    setConfigurationValues(2, Set.of(500));

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining(CONFIG_ENDPOINT_URI.toString())
        .hasMessageContaining("Error retrieving configured oidc endpoints")
        .hasMessageContaining("Request Headers [")
        .hasMessageContaining("Response Headers [")
        .hasMessageContaining("Http status code 500");
    Mockito.verify(restOperationsMock, times(3))
        .exchange(eq(CONFIG_ENDPOINT_URI), eq(HttpMethod.GET), any(), eq(String.class));
  }

  @Test
  public void retrieveTokenKeys_interruptedExceptionDuringRetry_logsWarning()
      throws OAuth2ServiceException {
    mockResponse(jsonOidcConfiguration, 500, 200);
    setConfigurationValues(1, Set.of(500));

    // Set up log capturing
    final Logger logger = (Logger) LoggerFactory.getLogger(SpringOidcConfigurationService.class);
    final ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);

    Thread.currentThread().interrupt(); // Simulate InterruptedException

    retrieveEndpoints();

    final List<ILoggingEvent> logsList = listAppender.list;
    assertThat(logsList).extracting(ILoggingEvent::getLevel).contains(Level.WARN);
    assertThat(logsList)
        .extracting(ILoggingEvent::getFormattedMessage)
        .contains("Thread.sleep has been interrupted. Retry starts now.");
    logger.detachAppender(listAppender);
    Mockito.verify(restOperationsMock, times(2))
        .exchange(eq(CONFIG_ENDPOINT_URI), eq(HttpMethod.GET), any(), eq(String.class));
  }

  private void mockResponse() {
    mockResponse(jsonOidcConfiguration, HttpStatus.OK.value());
  }

  private void mockResponse(final String responseAsString, final Integer... statusCodes) {
    final List<ResponseEntity<String>> responses =
        Arrays.stream(statusCodes)
            .map(
                statusCode ->
                    new ResponseEntity<>(responseAsString, HttpStatusCode.valueOf(statusCode)))
            .toList();
    final AtomicInteger index = new AtomicInteger(0);
    when(restOperationsMock.exchange(any(URI.class), eq(HttpMethod.GET), any(), eq(String.class)))
        .thenAnswer(
            invocation -> {
              final int currentIndex = index.getAndIncrement();
              return responses.get(currentIndex);
            });
  }

  private void setConfigurationValues(
      final int maxRetryAttempts, final Set<Integer> retryStatusCodes) {
    final SpringTokenClientConfiguration config = SpringTokenClientConfiguration.getInstance();
    config.setRetryEnabled(true);
    config.setMaxRetryAttempts(maxRetryAttempts);
    config.setRetryStatusCodes(retryStatusCodes);
    config.setRetryDelayTime(0L);
  }

  private OAuth2ServiceEndpointsProvider retrieveEndpoints() throws OAuth2ServiceException {
    return retrieveEndpoints(CONFIG_ENDPOINT_URI);
  }

  private OAuth2ServiceEndpointsProvider retrieveEndpoints(final URI endpointsEndpointUri)
      throws OAuth2ServiceException {
    return cut.retrieveEndpoints(endpointsEndpointUri);
  }
}
