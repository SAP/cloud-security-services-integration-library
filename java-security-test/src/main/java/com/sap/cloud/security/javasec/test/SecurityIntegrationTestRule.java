package com.sap.cloud.security.javasec.test;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;
import org.apache.commons.io.IOUtils;
import org.junit.rules.ExternalResource;
import org.junit.rules.TemporaryFolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

public class SecurityIntegrationTestRule extends ExternalResource {

	private static final Logger logger = LoggerFactory.getLogger(SecurityIntegrationTestRule.class);
	private static final String TOKEN_KEYS = "/token_keys"; // TODO XSUAA specific OAuth2ServiceEndpointsProvider.getJwksUri

	private final RSAKeys keys;
	private final JwtGenerator jwtGenerator;

	private int wireMockPort = 33195;
	private WireMockRule wireMockRule;

	private boolean useApplicationServer;
	private Tomcat tomcat;
	private String webappDir;
	private int tomcatPort = 8181;
	private TemporaryFolder baseDir;

	public SecurityIntegrationTestRule(Service service) {
		keys = RSAKeys.generate();
		jwtGenerator = JwtGenerator.getInstance(service);
	}

	public SecurityIntegrationTestRule setPort(int port) {
		wireMockPort = port;
		return this;
	}

	public SecurityIntegrationTestRule useApplicationServer(String pathToWebAppDir) {
		webappDir = pathToWebAppDir;
		useApplicationServer = true;
		return this;
	}

	public SecurityIntegrationTestRule useApplicationServer(String pathToWebAppDir, int port) {
		webappDir = pathToWebAppDir;
		useApplicationServer = true;
		tomcatPort = port;
		return this;
	}

	public JwtGenerator getPreconfiguredJwtGenerator() {
		String tokenKeysUrl = String.format("http://localhost:%d/%s", wireMockPort, TOKEN_KEYS);
		return jwtGenerator
				.withHeaderParameter("jku", tokenKeysUrl)
				.withClaim("cid", "sb-clientId!20")
				.withPrivateKey(keys.getPrivate());
	}

	public Token getAccessToken() {
		return getPreconfiguredJwtGenerator().createToken();
	}

	@Override
	protected void before() throws IOException {
		if (useApplicationServer) {
			startTomcat();
		}
		wireMockRule = new WireMockRule(options().port(wireMockPort));
		wireMockRule.start();
		wireMockRule.stubFor(get(urlEqualTo(TOKEN_KEYS))
				.willReturn(aResponse().withBody(createDefaultTokenKeyResponse())));
	}

	@Override
	protected void after() {
		wireMockRule.shutdown();
		if (useApplicationServer) {
			try {
				tomcat.stop();
				tomcat.destroy();
				baseDir.delete();
			} catch (LifecycleException e) {
				logger.error("Failed to properly stop the tomcat server!");
				throw new RuntimeException(e);
			}
		}
	}

	private String createDefaultTokenKeyResponse() throws IOException {
		return IOUtils.resourceToString("/token_keys_template.json", StandardCharsets.UTF_8)
				.replace("$kid", "default-kid")
				.replace("$public_key", Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()));
	}

	private void startTomcat() throws IOException {
		baseDir = new TemporaryFolder();
		baseDir.create();
		tomcat = new Tomcat();
		tomcat.setBaseDir(baseDir.getRoot().getAbsolutePath());
		tomcat.setPort(tomcatPort);
		try {
			tomcat.addWebapp("", new File(webappDir).getAbsolutePath());
			tomcat.start();
		} catch (LifecycleException | ServletException e) {
			logger.error("Failed to start the tomcat server!");
			throw new RuntimeException(e);
		}
	}
}
