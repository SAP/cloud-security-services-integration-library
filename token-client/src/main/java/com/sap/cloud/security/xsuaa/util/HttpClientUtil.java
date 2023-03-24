/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import org.apache.hc.core5.http.io.HttpClientResponseHandler;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class HttpClientUtil {

	public static final HttpClientResponseHandler<Integer> STATUS_CODE_EXTRACTOR = response -> response.getCode();

	private HttpClientUtil() {
		// use static fields and methods
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
