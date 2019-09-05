package com.sap.cloud.security.xsuaa.mock;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.core.env.PropertySource;
import org.springframework.util.Assert;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockWebServer;

public class XsuaaMockWebServer extends PropertySource<MockWebServer> implements DisposableBean {

	public static final String MOCK_XSUAA_PROPERTY_SOURCE_NAME = "mockxsuaaserver";
	public static final String MOCK_XSUAA_URL = "mockxsuaaserver.url";
	// must match the port defined in JwtGenerator
	private static final int MOCK_XSUAA_DEFAULT_PORT = 33195;

	private static final Log logger = LogFactory.getLog(XsuaaMockWebServer.class);

	private static boolean started;

	private final int port;

	public XsuaaMockWebServer() {
		this(MOCK_XSUAA_DEFAULT_PORT);
	}

	/**
	 * Overwrites the port the mock server listens to.
	 *
	 * @param port
	 * 			the port the mock server listens to.
	 */
	public XsuaaMockWebServer(int port) {
		super(MOCK_XSUAA_PROPERTY_SOURCE_NAME, createMockWebServer(new XsuaaRequestDispatcher()));
		this.port = port;
	}

	/**
	 * Overwrites the dispatcher used to match incoming requests to mock responses.
	 * The default dispatcher simply serves a fixed sequence of responses from a
	 * queue; custom dispatchers can vary the response based on timing or the
	 * content of the request.
	 *
	 * @param dispatcher
	 *            the dispatcher to be used
	 */
	public XsuaaMockWebServer(Dispatcher dispatcher) {
		super(MOCK_XSUAA_PROPERTY_SOURCE_NAME, createMockWebServer(dispatcher));
		port = MOCK_XSUAA_DEFAULT_PORT;
	}

	private static MockWebServer createMockWebServer(Dispatcher dispatcher) {
		Assert.notNull(dispatcher, "Dispatcher required");
		MockWebServer mockWebServer = new MockWebServer();
		mockWebServer.setDispatcher(dispatcher);
		return mockWebServer;
	}

	@Override
	public Object getProperty(String name) {
		if ((name.equals(MOCK_XSUAA_URL) || name.equals(MOCK_XSUAA_PROPERTY_SOURCE_NAME))) {
			MockWebServer mockWebServer = getSource();
			if (!this.started) {
				intializeMockXsuaa(mockWebServer);
			}
			return getUrl(mockWebServer);
		} else {
			return null;
		}
	}

	@Override
	public void destroy() throws Exception {
		getSource().shutdown();
	}

	private String getUrl(MockWebServer mockWebServer) {
		String url = mockWebServer.url("").url().toExternalForm();
		return url.substring(0, url.length() - 1).replace("127.0.0.1", "localhost");
	}

	private void intializeMockXsuaa(MockWebServer mockWebServer) {
		try {
			mockWebServer.start(port);
			this.started = true;
			logger.warn(
					">>>>>>>>>>>Started Xsuaa mock Server that provides public keys for offline JWT Token validation. NEVER run in productive environment!<<<<<<");
		} catch (IllegalStateException | IOException e) {
			throw new RuntimeException(
					String.format("Could not start XSUAA mock webserver (localhost:%d). " +
							"Make sure that it is not yet started in another process.", port),
					e);
		}
	}
}