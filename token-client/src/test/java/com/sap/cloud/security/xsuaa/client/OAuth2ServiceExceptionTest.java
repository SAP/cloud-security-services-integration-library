package com.sap.cloud.security.xsuaa.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class OAuth2ServiceExceptionTest {
  public static final String SERVICE_EXCEPTION = "Service Exception";
  private static final List<String> requestHeaders =
      List.of("requestHeader1=value1", "requestHeader2=value2");
  private static final List<String> responseHeaders =
      List.of("responseHeader1=value1", "responseHeader2=value2");

	private static OAuth2ServiceException builtWithHeaders;
  private static OAuth2ServiceException createdWithHeaders;

  @BeforeAll
  static void setup() {
    builtWithHeaders =
        OAuth2ServiceException.builder(SERVICE_EXCEPTION)
            .withResponseHeaders(responseHeaders.toArray(String[]::new))
            .withRequestHeaders(requestHeaders.toArray(String[]::new))
            .withStatusCode(400)
            .build();
    createdWithHeaders = new OAuth2ServiceException(SERVICE_EXCEPTION, 400, requestHeaders);
  }

  @Test
  void testWithHeaders_builtWithHeaders_headersAreParsedIntoMessageBlock() {
    assertThat(builtWithHeaders.getHeaders().size(), is(4));
    assertTrue(builtWithHeaders.getMessage().contains(SERVICE_EXCEPTION));
    assertTrue(
        builtWithHeaders
            .getMessage()
            .contains("Request Headers [requestHeader1=value1, requestHeader2=value2]"));
    assertTrue(
        builtWithHeaders
            .getMessage()
            .contains("Response Headers [responseHeader1=value1, responseHeader2=value2]"));
    assertEquals(400, builtWithHeaders.getHttpStatusCode());
  }

  @Test
  void testWithHeaders_createdWithHeaders_headersAreNotParsedIntoMessageBlock() {
    assertThat(createdWithHeaders.getHeaders().size(), is(2));
    assertTrue(createdWithHeaders.getMessage().contains(SERVICE_EXCEPTION));
    assertFalse(
        createdWithHeaders
            .getMessage()
            .contains("Request Headers [requestHeader1=value1, requestHeader2=value2]"));
    assertFalse(
        createdWithHeaders
            .getMessage()
            .contains("Response Headers [responseHeader1=value1, responseHeader2=value2]"));
    assertEquals(400, createdWithHeaders.getHttpStatusCode());
  }

  @Test
  void testWithoutHeaders() {
    final OAuth2ServiceException exception =
        OAuth2ServiceException.builder(SERVICE_EXCEPTION).withStatusCode(500).build();
    assertTrue(exception.getHeaders().isEmpty());
    assertEquals(500, exception.getHttpStatusCode());
    assertTrue(exception.getMessage().contains(SERVICE_EXCEPTION));
  }

  @Test
  void testNullHeaders() {
    final OAuth2ServiceException exception =
        new OAuth2ServiceException(SERVICE_EXCEPTION, 404, null);
    assertTrue(exception.getHeaders().isEmpty());
    assertEquals(404, exception.getHttpStatusCode());
    assertTrue(exception.getMessage().contains(SERVICE_EXCEPTION));
  }
}
