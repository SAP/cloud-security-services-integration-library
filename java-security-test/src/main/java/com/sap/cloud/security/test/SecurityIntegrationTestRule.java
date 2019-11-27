package com.sap.cloud.security.test;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.StandardRoot;
import org.apache.commons.io.IOUtils;
import org.junit.rules.ExternalResource;
import org.junit.rules.TemporaryFolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.ServletException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

public class SecurityIntegrationTestRule extends ExternalResource {

	private static final Logger logger = LoggerFactory.getLogger(SecurityIntegrationTestRule.class);
	private static final String LOCALHOST_PATTERN = "http://localhost:%d";

	private RSAKeys keys;
	private JwtGenerator jwtGenerator;

	private int wireMockPort = 33195;
	private WireMockRule wireMockRule;

	private boolean useApplicationServer;
	private Tomcat tomcat;
	private String webappDir;
	private int tomcatPort = 44195;
	private TemporaryFolder baseDir;
	private Service service;

	private SecurityIntegrationTestRule() {
		// see factory method getInstance()
	}

	public static SecurityIntegrationTestRule getInstance(Service service) {
		SecurityIntegrationTestRule instance = new SecurityIntegrationTestRule();
		instance.keys = RSAKeys.generate();
		instance.jwtGenerator = JwtGenerator.getInstance(service);
		instance.service = service;
		return instance;
	}

	/**
	 * Specifies an embedded Tomcat as application server.
	 * It needs to be configured before the {@link #before()} method.
	 *
	 * @param pathToWebAppDir e.g. "src/test/webapp"
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule useApplicationServer(String pathToWebAppDir) {
		return useApplicationServer(pathToWebAppDir, tomcatPort);
	}

	/**
	 * Specifies an embedded Tomcat as application server.
	 * It needs to be configured before the {@link #before()} method.
	 *
	 * @param pathToWebAppDir e.g. "src/test/webapp"
	 * @param port the port on which the application service is started.
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule useApplicationServer(String pathToWebAppDir, int port) {
		webappDir = pathToWebAppDir;
		useApplicationServer = true;
		tomcatPort = port;
		return this;
	}

	/**
	 * Overwrites the port on which the wire mock server runs.
	 * It needs to be configured before the {@link #before()} method.
	 *
	 * @param wireMockPort the port on which the wire mock service is started.
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule setPort(int wireMockPort) {
		this.wireMockPort = wireMockPort;
		return this;
	}

	/**
	 * Overwrites the private/public key pair to be used.
	 * The private key is used to sign the jwt token.
	 * The public key is provided by jwks endpoint (on behalf of WireMock).
	 *
	 * It needs to be configured before the {@link #before()} method.
	 *
	 * @param keys the private/public key pair.
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule setKeys(RSAKeys keys) {
		this.keys = keys;
		return this;
	}

	/**
	 * Note: the JwtGenerator is fully configured as part of {@link #before()} method.
	 */
	public JwtGenerator getPreconfiguredJwtGenerator() {
		return jwtGenerator;
	}

	/**
	 * Allows to stub further endpoints of the identity service.
	 * Returns null if not yet initialized as part of {@link #before()} method.
	 * You can find a detailed explanation on how to configure wire mock here: http://wiremock.org/docs/getting-started/
	 */
	@Nullable
	public WireMockRule getWireMockRule() {
		return wireMockRule;
	}

	/**
	 * Returns the URI of the embedded tomcat application server or null if not specified.
	 */
	@Nullable
	public String getAppServerUri() {
		if(!useApplicationServer) {
			return null;
		}
		return String.format(LOCALHOST_PATTERN, tomcatPort);
	}

	public Token createToken() {
		return getPreconfiguredJwtGenerator().createToken();
	}

	@Override
	protected void before() throws IOException {
		// start application server (for integration tests)
		if (useApplicationServer) {
			startTomcat();
		}

		// prepare endpoints provider
		OAuth2ServiceEndpointsProvider endpointsProvider = null;
		switch (service) {
		case XSUAA:
			endpointsProvider = new XsuaaDefaultEndpoints(String.format(LOCALHOST_PATTERN, wireMockPort));
			// configure predefined JwtGenerator
			jwtGenerator.withHeaderParameter(TokenHeader.JWKS_URL, endpointsProvider.getJwksUri().toString())
					.withClaim(TokenClaims.XSUAA.CLIENT_ID, "sb-clientId!20")
					.withPrivateKey(keys.getPrivate());
			// TODO check for feature parity in the spring-xsuaa-test JwtGenerator
			break;
		default:
			throw new IllegalStateException("Service " + service + " is not yet supported.");
		}

		// starts WireMock (to stub communication to identity service)
		wireMockRule = new WireMockRule(options().port(wireMockPort));
		wireMockRule.start();
		wireMockRule.stubFor(get(urlEqualTo(endpointsProvider.getJwksUri().getPath()))
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
			Context context = tomcat.addWebapp("", new File(webappDir).getAbsolutePath());
			File additionWebInfClasses = new File("target/classes");
			WebResourceRoot resources = new StandardRoot(context);
			resources.addPreResources(new DirResourceSet(resources, "/WEB-INF/classes", additionWebInfClasses.getAbsolutePath(), "/"));
			context.setResources(resources);
			tomcat.start();
		} catch (LifecycleException | ServletException e) {
			logger.error("Failed to start the tomcat server on port {}!", tomcatPort);
			throw new RuntimeException(e);
		}
	}
}
