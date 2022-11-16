/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.mock;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.PropertySource;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockWebServer;

/**
 * Starts a mock for xsuaa (user account and authentication) service on
 * localhost.
 */
public class XsuaaMockWebServer extends PropertySource<MockWebServer> {

	public static final String MOCK_XSUAA_PROPERTY_SOURCE_NAME = "mockxsuaaserver";
	public static final String MOCK_XSUAA_URL = "mockxsuaaserver.url";
	// must match the port defined in JwtGenerator
	static final int MOCK_XSUAA_DEFAULT_PORT = 33195;
	private final int port;
	private boolean isStarted;

	private static final Logger log = LoggerFactory.getLogger(XsuaaMockWebServer.class);

	private static Map<Integer, String> startedWebServer = new ConcurrentHashMap<>();

	public XsuaaMockWebServer() {
		this(MOCK_XSUAA_DEFAULT_PORT);
	}

	/**
	 * Initializes a Mock Web Server object on a given port.
	 *
	 * @param port
	 *            the port the mock server should listen to. Use '0' in case you
	 *            want to use a random port. Per specified port you can only start
	 *            one mock web server instance.
	 */
	public XsuaaMockWebServer(int port) {
		super(MOCK_XSUAA_PROPERTY_SOURCE_NAME, createMockWebServer(new XsuaaRequestDispatcher()));
		this.port = port;
	}

	/**
	 *
	 * Initializes a Mock Web Server object on default port '33195'.
	 *
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
			if (!startedWebServer.containsKey(port)) {
				intializeMockXsuaa(getSource(), port);
				isStarted = true;
			}
			String url = startedWebServer.get(port);
			log.info("return Mock Server url {} as property", url);
			return url;
		} else {
			return null;
		}
	}

	/**
	 * Shuts the server down, but only if it is started.
	 * 
	 * @throws IOException
	 */
	public void destroy() throws IOException {
		if (isStarted) { // if XsuaaMockWebServer instance contains server (getSource()) which is started
			getSource().shutdown(); // performs a shutdown only in case if getSource().started = true
			log.info(">>>>>>>>>>> Stopped Xsuaa Mock Server (MockWebServer[{}]) ", port);
			startedWebServer.remove(port);
		}
	}

	private static void intializeMockXsuaa(MockWebServer mockWebServer, int port) {
		try {
			mockWebServer.start(port);
			startedWebServer.put(port, getUrlAndStartIfNotStarted(mockWebServer));
			log.warn(
					">>>>>>>>>>> Started Xsuaa Mock Server ({}) that provides public keys for offline JWT Token validation. NEVER run in productive environment!<<<<<<",
					mockWebServer.url(""));
		} catch (IllegalStateException | IOException e) {
			throw new IllegalStateException(
					String.format("Could not start XSUAA Mock webserver (port:%d). " +
							"Make sure that it is not yet started in another process.", port),
					e);
		}
	}

	private static String getUrlAndStartIfNotStarted(MockWebServer mockWebServer) {
		String url = mockWebServer.url("").url().toExternalForm();
		url = UriComponentsBuilder.fromHttpUrl(url).host("localhost").build().toUriString();
		return url.substring(0, url.length() - 1); // removes trailing "/"
	}
}