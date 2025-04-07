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
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.client.DefaultTokenClientConfiguration;
import com.sap.cloud.security.xsuaa.util.HttpClientTestFactory;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;

public class DefaultOidcConfigurationServiceTest {
  public static final URI CONFIG_ENDPOINT_URI =
      URI.create("https://sub.myauth.com" + DISCOVERY_ENDPOINT_DEFAULT);
  private final String jsonOidcConfiguration;
  private static final String ERROR_MESSAGE = "Error message";
  private CloseableHttpClient httpClientMock;
  private DefaultOidcConfigurationService cut;

  public DefaultOidcConfigurationServiceTest() throws IOException {
    jsonOidcConfiguration =
        IOUtils.resourceToString("/oidcConfiguration.json", StandardCharsets.UTF_8);
  }

  @Before
  public void setUp() {
    httpClientMock = Mockito.mock(CloseableHttpClient.class);
    cut = new DefaultOidcConfigurationService(httpClientMock);
  }

  @Test
  public void retrieveEndpoints_httpClientIsNull_throwsException() {
    assertThatThrownBy(() -> new DefaultOidcConfigurationService(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void retrieveEndpoints_parameterIsNull_throwsException() {
    assertThatThrownBy(() -> cut.retrieveEndpoints(null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void retrieveEndpoints_badRequest_throwsException() {
    mockResponse(ERROR_MESSAGE, 400);

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Http status code 400")
        .hasMessageContaining("Response Headers [User-Agent: token-client/3.5.9]")
        .hasMessageContaining("Error retrieving configured oidc endpoints");
  }

  @Test
  public void retrieveEndpoints_executesHttpGetRequestWithCorrectURI() throws IOException {
    mockResponse();

    retrieveEndpoints();

    Mockito.verify(httpClientMock, times(1))
        .execute(argThat(isHttpGetAndContainsCorrectURI()), any(ResponseHandler.class));
  }

  @Test
  public void retrieveEndpoints_IOExceptionOccurs_throwsServiceException() throws IOException {
    when(httpClientMock.execute(any(), any(ResponseHandler.class)))
        .thenThrow(new IOException(ERROR_MESSAGE));

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .extracting(OAuth2ServiceException.class::cast)
        .extracting(OAuth2ServiceException::getHttpStatusCode)
        .isEqualTo(0);
  }

  @Test
  public void retrieveTokenKeys_errorOccursDuringRetry_throwsServiceException() throws IOException {
    mockResponse(ERROR_MESSAGE, 500, 400);
    setConfigurationValues(1, Set.of(500));

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Http status code 400")
        .hasMessageContaining("Response Headers [User-Agent: token-client/3.5.9]")
        .hasMessageContaining("Error retrieving configured oidc endpoints");
    Mockito.verify(httpClientMock, times(2))
        .execute(any(HttpUriRequest.class), any(ResponseHandler.class));
  }

  @Test
  public void retrieveIssuerEndpoints_executesHttpGetRequestWithCorrectURI() {
    final URI discoveryEndpoint1 =
        DefaultOidcConfigurationService.getDiscoveryEndpointUri("https://sub.myauth.com");
    final URI discoveryEndpoint2 =
        DefaultOidcConfigurationService.getDiscoveryEndpointUri("https://sub.myauth.com/");
    final URI discoveryEndpoint3 =
        DefaultOidcConfigurationService.getDiscoveryEndpointUri("https://sub.myauth.com/path");
    final URI discoveryEndpoint4 =
        DefaultOidcConfigurationService.getDiscoveryEndpointUri("https://sub.myauth.com//path");
    final URI discoveryEndpoint5 =
        DefaultOidcConfigurationService.getDiscoveryEndpointUri("sub.myauth.com/path");

    assertThat(discoveryEndpoint1)
        .hasToString("https://sub.myauth.com/.well-known/openid-configuration");
    assertThat(discoveryEndpoint2)
        .hasToString("https://sub.myauth.com/.well-known/openid-configuration");
    assertThat(discoveryEndpoint3)
        .hasToString("https://sub.myauth.com/path/.well-known/openid-configuration");
    assertThat(discoveryEndpoint4)
        .hasToString("https://sub.myauth.com/path/.well-known/openid-configuration");
    assertThat(discoveryEndpoint5)
        .hasToString("https://sub.myauth.com/path/.well-known/openid-configuration");
  }

  @Test
  public void retrieveEndpoints_containsBothKeys() throws IOException {
    mockResponse();

    final OAuth2ServiceEndpointsProvider result = retrieveEndpoints();

    assertThat(result.getTokenEndpoint()).hasToString("http://localhost/oauth/token");
    assertThat(result.getJwksUri()).hasToString("http://localhost/token_keys");
    assertThat(result.getAuthorizeEndpoint()).hasToString("http://localhost/oauth/authorize");
  }

  @Test
  public void retrieveTokenKeys_firstResponseNotOk_executesRetrySuccessfullyWithOKResponse()
      throws IOException {
    mockResponse(jsonOidcConfiguration, 500, 200);
    setConfigurationValues(1, Set.of(500));

    final OAuth2ServiceEndpointsProvider result = retrieveEndpoints();

    Mockito.verify(httpClientMock, times(2))
        .execute(any(HttpUriRequest.class), any(ResponseHandler.class));
    assertThat(result).isNotNull();
  }

  @Test
  public void retrieveTokenKeys_allRetryableStatusCodes_executesRetrySuccessfullyWithBadResponse()
      throws IOException {
    mockResponse(ERROR_MESSAGE, 408, 429, 500, 502, 503, 504, 400);
    setConfigurationValues(10, Set.of(408, 429, 500, 502, 503, 504));

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Error retrieving configured oidc endpoints")
        .hasMessageContaining("Response Headers [User-Agent: token-client/3.5.9]")
        .hasMessageContaining("Http status code 400");
    Mockito.verify(httpClientMock, times(7))
        .execute(any(HttpUriRequest.class), any(ResponseHandler.class));
  }

  @Test
  public void retrieveTokenKeys_noRetryableStatusCodesSet_executesNoRetry() throws IOException {
    mockResponse(ERROR_MESSAGE, 500);
    setConfigurationValues(10, Set.of());

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Error retrieving configured oidc endpoints")
        .hasMessageContaining("Response Headers [User-Agent: token-client/3.5.9]")
        .hasMessageContaining("Http status code 500");
    Mockito.verify(httpClientMock, times(1))
        .execute(any(HttpUriRequest.class), any(ResponseHandler.class));
  }

  @Test
  public void retrieveTokenKeys_retryLogic_maxAttemptsReached_throwsException() throws IOException {
    mockResponse(ERROR_MESSAGE, 500, 500, 500, 500);
    setConfigurationValues(2, Set.of(500));

    assertThatThrownBy(this::retrieveEndpoints)
        .isInstanceOf(OAuth2ServiceException.class)
        .hasMessageContaining(ERROR_MESSAGE)
        .hasMessageContaining("Error retrieving configured oidc endpoints")
        .hasMessageContaining("Response Headers [User-Agent: token-client/3.5.9]")
        .hasMessageContaining("Http status code 500");
    Mockito.verify(httpClientMock, times(3))
        .execute(any(HttpUriRequest.class), any(ResponseHandler.class));
  }

  @Test
  public void retrieveTokenKeys_interruptedExceptionDuringRetry_logsWarning() throws IOException {
    mockResponse(jsonOidcConfiguration, 500, 200);
    setConfigurationValues(1, Set.of(500));

    // Set up log capturing
    final Logger logger = (Logger) LoggerFactory.getLogger(DefaultOidcConfigurationService.class);
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
    Mockito.verify(httpClientMock, times(2))
        .execute(any(HttpUriRequest.class), any(ResponseHandler.class));
  }

  private void mockResponse() throws IOException {
    final CloseableHttpResponse response =
        HttpClientTestFactory.createHttpResponse(jsonOidcConfiguration);
    when(httpClientMock.execute(any(), any(ResponseHandler.class)))
        .thenAnswer(
            invocation -> {
              final ResponseHandler responseHandler = invocation.getArgument(1);
              return responseHandler.handleResponse(response);
            });
  }

  private OAuth2ServiceEndpointsProvider retrieveEndpoints() throws OAuth2ServiceException {
    return cut.retrieveEndpoints(CONFIG_ENDPOINT_URI);
  }

  private ArgumentMatcher<HttpUriRequest> isHttpGetAndContainsCorrectURI() {
    return (httpGet) -> {
      final boolean hasCorrectURI;
      hasCorrectURI = httpGet.getURI().equals(CONFIG_ENDPOINT_URI);
      final boolean correctMethod = httpGet.getMethod().equals(HttpMethod.GET.toString());
      return hasCorrectURI && correctMethod;
    };
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
      when(httpClientMock.execute(any(), any(ResponseHandler.class)))
          .thenAnswer(
              invocation -> {
                final ResponseHandler responseHandler = invocation.getArgument(1);
                final CloseableHttpResponse response = responses.get(index.getAndIncrement());
                return responseHandler.handleResponse(response);
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
}
