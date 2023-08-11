package com.sap.cloud.security.xsuaa.client;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OAuth2ServiceExceptionTest {
    public static final String SERVICE_EXCEPTION = "Service Exception";
    private static List<String> headers;
    private static OAuth2ServiceException builtWithHeaders;
    private static OAuth2ServiceException createdWithHeaders;

    @BeforeAll
    static void setup() {
        headers = new ArrayList<>();
        headers.add("header1=value1");
        headers.add("header2=value2");
        builtWithHeaders = OAuth2ServiceException.builder(SERVICE_EXCEPTION).withHeaders(headers.toArray(new String[0])).withStatusCode(400).build();
        createdWithHeaders = new OAuth2ServiceException(SERVICE_EXCEPTION, 400, headers);
    }

    @Test
    void testWithHeaders() {
        assertIterableEquals(headers, builtWithHeaders.getHeaders());
        assertTrue(builtWithHeaders.getMessage().contains(SERVICE_EXCEPTION));
        assertTrue(builtWithHeaders.getMessage().contains("[header1=value1, header2=value2]"));
        assertEquals(400, builtWithHeaders.getHttpStatusCode());

        assertIterableEquals(headers, createdWithHeaders.getHeaders());
        assertTrue(createdWithHeaders.getMessage().contains(SERVICE_EXCEPTION));
        assertFalse(createdWithHeaders.getMessage().contains("[header1=value1, header2=value2]"));
        assertEquals(400, createdWithHeaders.getHttpStatusCode());
    }
}