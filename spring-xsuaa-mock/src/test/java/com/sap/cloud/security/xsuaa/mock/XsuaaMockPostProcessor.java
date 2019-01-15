package com.sap.cloud.security.xsuaa.mock;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpStatus;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

import java.nio.charset.StandardCharsets;

public class XsuaaMockPostProcessor implements EnvironmentPostProcessor, DisposableBean {

	private final XsuaaMockWebServer mockAuthorizationServer;

	public XsuaaMockPostProcessor() {
		mockAuthorizationServer = new XsuaaMockWebServer(new MyDispatcher());
	}

	@Override
	public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
		if (environment.acceptsProfiles(Profiles.of("uaamock"))) {
			environment.getPropertySources().addFirst(this.mockAuthorizationServer);
		}
	}

	@Override
	public void destroy() throws Exception {
		this.mockAuthorizationServer.destroy();
	}

	private static class MyDispatcher extends XsuaaRequestDispatcher {

		@Override
		public MockResponse dispatch(RecordedRequest request) {
			if ("/customdomain/token_keys".equals(request.getPath())) {
				return getTokenKeyForKeyId(PATH_TOKEN_KEYS_TEMPLATE, PATH_PUBLIC_KEY, "legacy-token-key-customdomain");
			} if ("/testdomain/token_keys".equals(request.getPath())) {
				return getResponseFromFile("/mock/testdomain_token_keys.json", HttpStatus.OK);
			}
			return super.dispatch(request);
		}
	}
}