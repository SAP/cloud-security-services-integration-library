package com.sap.cloud.security.xsuaa.client;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OAuth2ServiceExceptionTest {
    public static final String SERVICE_EXCEPTION = "Service Exception";
    private static List<String> headers;
    private static OAuth2ServiceException builtWithHeaders;
    private static OAuth2ServiceException createdWithHeaders;

    @BeforeAll
    static void setup() {
        headers = List.of("header1=value1", "header2=value2");
        builtWithHeaders = OAuth2ServiceException.builder(SERVICE_EXCEPTION).withHeaders(headers.toArray(String[]::new)).build();
        createdWithHeaders = new OAuth2ServiceException(SERVICE_EXCEPTION, 400, headers);
    }

    @Test
    void testWithHeaders() {
        assertIterableEquals(headers, builtWithHeaders.getHeaders());
        assertTrue(builtWithHeaders.getMessage().contains(SERVICE_EXCEPTION));
        assertTrue(builtWithHeaders.getMessage().contains("[header1=value1, header2=value2]"));

        assertIterableEquals(headers, createdWithHeaders.getHeaders());
        assertTrue(createdWithHeaders.getMessage().contains(SERVICE_EXCEPTION));
        assertFalse(createdWithHeaders.getMessage().contains("[header1=value1, header2=value2]"));
    }
}