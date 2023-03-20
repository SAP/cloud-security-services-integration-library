package testservice.api;

import java.io.IOException;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.test.context.TestPropertySource;

import okhttp3.mockwebserver.MockWebServer;

@TestPropertySource(properties = { "xsuaa.xsappname=java-hello-world", "xsuaa.clientid=sb-java-hello-world",
		"xsuaa.url=http://localhost:33195", "xsuaa.uaadomain=localhost" })
public class MockXsuaaServerConfiguration {
	private static final int DEFAULT_PORT = 33195;
	private static MockWebServer server;

	@BeforeAll
	static void beforeAll() throws IOException {
		initServer();
	}

	private static void initServer() throws IOException {
		if (server == null) {
			server = new MockWebServer();
			server.setDispatcher(new XsuaaRequestDispatcher());
			server.start(DEFAULT_PORT);
		}
	}

}
