package com.sap.cloud.security.xsuaa.mock;

import java.io.IOException;
import java.nio.charset.Charset;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.core.env.PropertySource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

public class MockAuthorizationServer extends PropertySource<MockWebServer> implements DisposableBean {

	public static final String MOCK_XSUAA_PROPERTY_SOURCE_NAME = "mockxsuaaserver";
	private static final String MOCK_XSUAA_URL = "mockxsuaaserver.url";

	private static final Log logger = LogFactory.getLog(MockAuthorizationServer.class);

	private boolean started;

	public MockAuthorizationServer() {
		super(MOCK_XSUAA_PROPERTY_SOURCE_NAME, new MockWebServer());
	}

	@Override
	public Object getProperty(String name) {
		if ((name.equals(MOCK_XSUAA_URL) || name.equals(MOCK_XSUAA_PROPERTY_SOURCE_NAME))) {
			return getUrl();
		} else {
			return null;
		}

	}

	@Override
	public void destroy() throws Exception {
		getSource().shutdown();
	}

	private String getUrl() {
		MockWebServer mockWebServer = getSource();
		if (!this.started) {
			intializeMockXsuaa(mockWebServer);
		}
		String url = mockWebServer.url("").url().toExternalForm();
		return url.substring(0, url.length() - 1);
	}

	private void intializeMockXsuaa(MockWebServer mockWebServer) {
		Dispatcher dispatcher = new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) throws InterruptedException {

				if ("/testdomain/token_keys".equals(request.getPath())) {
					return getResponse("/mock/testdomain_token_keys.txt", 200);
				}
				if ("/otherdomain/token_keys".equals(request.getPath())) {
					return getResponse("/mock/otherdomain_token_keys.txt", 200);
				}
				if (request.getPath().endsWith("/token_keys")) {
					return getResponse("/mock/testdomain_token_keys.txt", 200);
				}
				if (request.getPath().startsWith("/oauth/token?grant_type=client_credentials")) {
					if ("basic YzE6czE=".equalsIgnoreCase(request.getHeader("authorization")) && "POST".equals(request.getMethod()) && request.getPath().contains("%7B%22az_attr%22:%7B%22a%22:%22b%22,%22c%22:%22d%22%7D%7D"))
						return getResponse("/mock/cc_token.txt", 200);
					else
						getResponse("/mock/404.txt", 404);
				}
				return getResponse("/mock/404.txt", 404);
			}
		};

		mockWebServer.setDispatcher(dispatcher);
		try {
			mockWebServer.start();
			this.started = true;
		} catch (IOException e) {
			throw new RuntimeException("Could not start " + mockWebServer, e);
		}
	}

	private static MockResponse getResponse(String path, int status) {
		String body;
		try {
			body = com.nimbusds.jose.util.IOUtils.readInputStreamToString(MockAuthorizationServer.class.getResourceAsStream(path), Charset.forName("utf-8"));
			return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setResponseCode(status).setBody(body);
		} catch (IOException e) {
			return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setResponseCode(500).setBody(e.getMessage());
		}
	}
}
