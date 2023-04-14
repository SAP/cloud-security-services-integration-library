/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import com.sap.cloud.security.xsuaa.Assertions;
import org.apache.http.HttpResponse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Properties;
import java.util.stream.Collectors;

public class HttpClientUtil {

	private HttpClientUtil() {
		// use static methods
	}

	public static String extractResponseBodyAsString(HttpResponse response) throws IOException {
		Assertions.assertNotNull(response, "response must not be null.");
		return new BufferedReader(new InputStreamReader(response.getEntity().getContent()))
				.lines().collect(Collectors.joining(System.lineSeparator()));
	}

	public static String getUserAgent() {
		Properties props = new Properties();
		InputStream stream = HttpClientUtil.class.getResourceAsStream("/token-client.properties");
		try {
			props.load(stream);
			return props.getProperty("artifactId") + "/" + props.getProperty("version");
		} catch (IOException | NullPointerException | IllegalArgumentException e) {
			return "token-client/0.0.0";
		}
	}

}
