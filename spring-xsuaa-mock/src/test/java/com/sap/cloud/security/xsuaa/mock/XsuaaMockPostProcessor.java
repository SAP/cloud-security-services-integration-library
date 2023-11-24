/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.mock;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpStatus;

public class XsuaaMockPostProcessor implements EnvironmentPostProcessor {

	private static final XsuaaMockWebServer mockAuthorizationServer = new XsuaaMockWebServer(new MyDispatcher());

	@Override
	public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
		if (environment.acceptsProfiles(Profiles.of("uaamock"))) {
			environment.getPropertySources().addFirst(mockAuthorizationServer);
		}
	}

	private static class MyDispatcher extends XsuaaRequestDispatcher {

		@Override
		public MockResponse dispatch(RecordedRequest request) {
			if ("/customdomain/token_keys".equals(request.getPath())) {
				return getTokenKeyForKeyId(PATH_TESTDOMAIN_TOKEN_KEYS, "legacy-token-key-customdomain");
			}
			if ("/testdomain/token_keys".equals(request.getPath())) {
				return getResponseFromFile("/mock/testdomain_token_keys.json", HttpStatus.OK);
			}
			return super.dispatch(request);
		}
	}
}