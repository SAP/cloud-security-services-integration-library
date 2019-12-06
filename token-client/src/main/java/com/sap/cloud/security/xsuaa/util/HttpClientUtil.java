package com.sap.cloud.security.xsuaa.util;

import org.apache.http.HttpResponse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

public class HttpClientUtil {

	private HttpClientUtil() {
		// use static methods
	}
	public static String extractResponseBodyAsString(HttpResponse response) throws IOException {
		return new BufferedReader(new InputStreamReader(response.getEntity().getContent()))
				.lines().collect(Collectors.joining(System.lineSeparator()));
	}

}
