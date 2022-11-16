/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.mock;

import java.nio.charset.StandardCharsets;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

public class MockPostProcessor implements EnvironmentPostProcessor {

	private static final XsuaaMockWebServer mockAuthorizationServer = new XsuaaMockWebServer(new MyDispatcher());

	@Override
	public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
		environment.getPropertySources().addFirst(mockAuthorizationServer);
	}

	private static class MyDispatcher extends XsuaaRequestDispatcher {

		@Override
		@java.lang.SuppressWarnings("squid:S2068")
		public MockResponse dispatch(RecordedRequest request) {
			if ("/otherdomain/token_keys".equals(request.getPath())) {
				return getResponseFromFile("/mock/otherdomain_token_keys.json", HttpStatus.OK);
			}
			if (request.getPath().equals("/oauth/token") && "POST".equals(request.getMethod())) {
				String body = request.getBody().readString(StandardCharsets.UTF_8);
				if (body.contains("grant_type=password") && body.contains("username=basic.user")
						&& body.contains("password=basic.password")) {
					try {
						return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
								.setResponseCode(HttpStatus.OK.value())
								.setBody(String.format("{\"expires_in\": 43199, \"access_token\": \"%s\"}",
										JWTUtil.createJWT("/password.txt", "testdomain")));
					} catch (Exception e) {
						e.printStackTrace();
						getResponse(RESPONSE_500, HttpStatus.INTERNAL_SERVER_ERROR);
					}
				}
				if (body.contains("grant_type=client_credentials")) {
					try {
						return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
								.setResponseCode(HttpStatus.OK.value()).setBody(String.format(
										"{\"expires_in\": 43199, \"access_token\": \"%s\"}",
										JWTUtil.createJWT("/cc.txt", "testdomain")));
					} catch (Exception e) {
						e.printStackTrace();
						getResponse(RESPONSE_500, HttpStatus.INTERNAL_SERVER_ERROR);
					}
				}
				getResponse(RESPONSE_401, HttpStatus.UNAUTHORIZED);
			}
			return super.dispatch(request);
		}
	}
}