package com.sap.cloud.security.xsuaa.client;

import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.http.HttpEntity;
import org.springframework.web.client.RestOperations;

import java.net.URI;
import java.util.Map;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;

public class RequestCaptorFactory {

	public static <T> ArgumentCaptor<HttpEntity<T>> createPostRequestCaptor(
			RestOperations mockRestOperations, URI tokenEndpoint) {
		ArgumentCaptor<HttpEntity<T>> requestEntityCaptor = ArgumentCaptor
				.forClass(HttpEntity.class);

		Mockito.verify(mockRestOperations, times(1))
				.postForEntity(
						eq(tokenEndpoint),
						requestEntityCaptor.capture(),
						eq(Map.class));

		return requestEntityCaptor;
	}

}
