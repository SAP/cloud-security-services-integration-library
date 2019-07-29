package com.sap.cloud.security.xsuaa.token.flows;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

public class RestTemplateMock extends RestTemplate {

	enum ResponseEntityContents {
		ACCESS_TOKEN, REFRESH_TOKEN;
	}

	boolean postForEntityCalled;
	URI expectedUri;
	HttpEntity<Void> expectedRequest;
	Class<?> expectedResponseType;
	String mockJwtValue;
	HttpStatus mockHttpStatus;
	ResponseEntityContents responseContents;

	public RestTemplateMock(URI expectedUri,
			HttpEntity<Void> expectedRequest,
			Class<?> expectedResponseType,
			String mockJwtValue,
			HttpStatus mockHttpStatus) {

		this(expectedUri, expectedRequest, expectedResponseType, mockJwtValue, mockHttpStatus,
				ResponseEntityContents.ACCESS_TOKEN);
	}

	public RestTemplateMock(URI expectedUri,
			HttpEntity<Void> expectedRequest,
			Class<?> expectedResponseType,
			String mockJwtValue,
			HttpStatus mockHttpStatus,
			ResponseEntityContents responseEntityContents) {

		this.expectedUri = expectedUri;
		this.expectedRequest = expectedRequest;
		this.expectedResponseType = expectedResponseType;
		this.mockJwtValue = mockJwtValue;
		this.mockHttpStatus = mockHttpStatus;
		this.responseContents = responseEntityContents;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public <T> ResponseEntity<T> postForEntity(URI uri, @Nullable Object request, Class<T> responseType)
			throws RestClientException {

		postForEntityCalled = true;

		assertNotNull("RestTemplate called with null-URI.", uri);
		assertNotNull("RestTemplate called with null-Request.", request);
		assertNotNull("RestTemplate called with null-ResponseType.", responseType);

		assertThat(uri).isEqualTo(expectedUri);
		assertThat(request).isEqualTo(expectedRequest);
		assertThat(responseType).isEqualTo(expectedResponseType);

		Map<String, Object> responseBody = new HashMap<String, Object>();

		switch (responseContents) {
		case ACCESS_TOKEN:
			responseBody.put("access_token", mockJwtValue);
		case REFRESH_TOKEN:
			responseBody.put("refresh_token", "dummyRefreshTokenValue");
		}

		return (ResponseEntity<T>) new ResponseEntity(responseBody, mockHttpStatus);
	}

	public void validateCallstate() {
		assertTrue("postForEntity was not called. Needs to be called to fetch token.", postForEntityCalled);
	}
}
