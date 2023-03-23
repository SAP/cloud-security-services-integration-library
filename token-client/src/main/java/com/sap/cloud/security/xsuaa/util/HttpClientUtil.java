/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import com.sap.cloud.security.xsuaa.Assertions;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.EntityUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Properties;
import java.util.stream.Collectors;

public class HttpClientUtil {

	public static final HttpClientResponseHandler<Integer> STATUS_CODE_EXTRACTOR = response -> response.getCode();
	public static final HttpClientResponseHandler<String> STRING_CONTENT_EXTRACTOR = response -> EntityUtils.toString(response.getEntity(), "UTF-8");

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
