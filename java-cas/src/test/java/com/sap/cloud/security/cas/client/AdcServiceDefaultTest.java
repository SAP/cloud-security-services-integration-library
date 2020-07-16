package com.sap.cloud.security.cas.client;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicStatusLine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

class AdcServiceDefaultTest {

	private AdcServiceDefault cut;
	private CloseableHttpClient httpClient;

	@BeforeEach
	void setUp() {
		httpClient = Mockito.mock(CloseableHttpClient.class);
		cut = new AdcServiceDefault(URI.create("http://localhost/"), httpClient);
	}

	@Test
	void isUserAuthorized_isTrue() throws IOException {
		CloseableHttpResponse responseMock = createResponse("{result: true}", HttpStatus.SC_OK);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(responseMock);

		AdcServiceResponse response = cut.isUserAuthorized(createRequest());

		assertTrue(response.getResult());
	}

	@Test
	void isUserAuthorized_isFalse() throws IOException {
		CloseableHttpResponse responseMock = createResponse("{result: false}", HttpStatus.SC_OK);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(responseMock);

		AdcServiceResponse response = cut.isUserAuthorized(createRequest());

		assertFalse(response.getResult());
	}

	@Test
	void isUserAuthorized_responseEmpty_isFalse() throws IOException {
		CloseableHttpResponse responseMock = createResponse("{}", HttpStatus.SC_OK);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(responseMock);

		AdcServiceResponse response = cut.isUserAuthorized(createRequest());

		assertFalse(response.getResult());
	}

	@Test
	void isUserAuthorized_httpNotFound_isFalse() throws IOException {
		CloseableHttpResponse responseMock = createResponse(HttpStatus.SC_NOT_FOUND);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(responseMock);

		AdcServiceResponse response = cut.isUserAuthorized(createRequest());

		assertFalse(response.getResult());
	}

	@Test
	void isUserAuthorized_httpCallFails_isFalse() throws IOException {
		when(httpClient.execute(any())).thenThrow(IOException.class);
		AdcServiceResponse response = cut.isUserAuthorized(createRequest());

		assertFalse(response.getResult());
	}

	@Test
	void ping() throws IOException {
		CloseableHttpResponse responseMock = createResponse(HttpStatus.SC_OK);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(responseMock);
		assertTrue(cut.ping());
	}

	@Test
	void ping_httpNotFound_isFalse() throws IOException {
		CloseableHttpResponse responseMock = createResponse(HttpStatus.SC_NOT_FOUND);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(responseMock);
		assertFalse(cut.ping());
	}

	@Test
	void ping_httpCallFails_isFalse() throws IOException {
		when(httpClient.execute(any())).thenThrow(IOException.class);
		assertFalse(cut.ping());
	}

	public static AdcServiceRequestDefault createRequest() {
		return new AdcServiceRequestDefault("zoneId", "userId");
	}

	private static CloseableHttpResponse createResponse(int statusCode) throws IOException {
		return createResponse("", statusCode);
	}

	private static CloseableHttpResponse createResponse(String responseBody, int statusCode) throws IOException {
		CloseableHttpResponse responseMock = Mockito.mock(CloseableHttpResponse.class);
		HttpEntity httpEntityMock = Mockito.mock(HttpEntity.class);
		when(responseMock.getEntity()).thenReturn(httpEntityMock);
		when(responseMock.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, statusCode, "None"));
		when(httpEntityMock.getContent()).thenReturn(new ByteArrayInputStream(responseBody.getBytes()));
		return responseMock;
	}

}