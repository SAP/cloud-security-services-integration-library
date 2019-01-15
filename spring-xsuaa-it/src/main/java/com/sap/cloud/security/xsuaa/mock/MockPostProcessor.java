package com.sap.cloud.security.xsuaa.mock;

import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

public class MockPostProcessor implements EnvironmentPostProcessor, DisposableBean {

	private final XsuaaMockWebServer mockAuthorizationServer;

	public MockPostProcessor() {
		mockAuthorizationServer = new XsuaaMockWebServer(new MyDispatcher());
	}

	@Override
	public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
		environment.getPropertySources().addFirst(this.mockAuthorizationServer);
	}

	@Override
	public void destroy() throws Exception {
		this.mockAuthorizationServer.destroy();
	}

	private static class MyDispatcher extends XsuaaRequestDispatcher {

		@Override
		public MockResponse dispatch(RecordedRequest request) {
			if ("/otherdomain/token_keys".equals(request.getPath())) {
				return getResponseFromFile("/mock/otherdomain_token_keys.json", HttpStatus.OK);
			}
			if (request.getPath().startsWith("/oauth/token?grant_type=client_credentials")) {
				if ("basic YzE6czE=".equalsIgnoreCase(request.getHeader("authorization")) && "POST".equals(request.getMethod()) && request.getPath().contains("%7B%22az_attr%22:%7B%22a%22:%22b%22,%22c%22:%22d%22%7D%7D"))
					return getResponseFromFile("/mock/cc_token.json", HttpStatus.OK);
				else
					getResponse(RESPONSE_404, HttpStatus.NOT_FOUND);
			}
			if (request.getPath().equals("/oauth/token")) {
				String body = request.getBody().readString(StandardCharsets.UTF_8);
				if ("basic c2ItamF2YS1oZWxsby13b3JsZDpteXNlY3JldC1iYXNpYw==".equalsIgnoreCase(request.getHeader("authorization")) && "POST".equals(request.getMethod()) && body.contains("username=basic.user") && body.contains("password=basic.password")) {

					try {
						return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setResponseCode(HttpStatus.OK.value()).setBody(String.format("{\"access_token\": \"%s\"}", JWTUtil.createJWT("/password.txt", "testdomain")));
					} catch (Exception e) {
						e.printStackTrace();
						getResponse(RESPONSE_500, HttpStatus.INTERNAL_SERVER_ERROR);
					}
				}
				if ("basic c2ItamF2YS1oZWxsby13b3JsZDpiYXNpYy5jbGllbnRzZWNyZXQ=".equalsIgnoreCase(request.getHeader("authorization")) && "POST".equals(request.getMethod()) && body.contains("grant_type=client_credentials")) {

					try {
						return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setResponseCode(HttpStatus.OK.value()).setBody(String.format("{\"access_token\": \"%s\"}", JWTUtil.createJWT("/cc.txt", "testdomain")));
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