package com.sap.cloud.security.test;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.rules.ExternalResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.Servlet;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

public class SecurityIntegrationTestRule extends ExternalResource {

	private static final Logger logger = LoggerFactory.getLogger(SecurityIntegrationTestRule.class);
	private static final String LOCALHOST_PATTERN = "http://localhost:%d";

	private RSAKeys keys;

	private int wireMockPort = 0;
	private WireMockRule wireMockRule;

	private boolean useApplicationServer;
	private int applicationServerPort = 0;
	private Server applicationServer;
	private Map<String, ServletHolder> applicationServletsByPath = new HashMap<>();
	private List<FilterHolder> applicationServletFilters = new ArrayList<>();

	private Service service;
	private String clientId;
	private String jwksUrl;

	private SecurityIntegrationTestRule() {
		// see factory method getInstance()
	}

	/**
	 * Creates an instance of the test rule for the given service.
	 * 
	 * @param service
	 *            the service for which the test rule should be created.
	 * @return the test rule instance.
	 */
	public static SecurityIntegrationTestRule getInstance(Service service) {
		SecurityIntegrationTestRule instance = new SecurityIntegrationTestRule();
		// TODO IAS
		/*if (service != Service.XSUAA) {
			throw new UnsupportedOperationException("Identity Service " + service + " is not yet supported.");
		}*/
		instance.keys = RSAKeys.generate();
		instance.service = service;
		return instance;
	}

	/**
	 * Specifies an embedded jetty as servlet server. It needs to be configured
	 * before the {@link #before()} method. If the port is set to 0, a free random
	 * port is chosen.
	 *
	 * @param port
	 *            the port on which the application service is started.
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule useApplicationServer(int port) {
		applicationServerPort = port;
		useApplicationServer = true;
		return this;
	}

	/**
	 * Specifies an embedded jetty as servlet server. It needs to be configured
	 * before the {@link #before()} method. The servlet server will listen on a free
	 * random port. Use {@link #getApplicationServerUri()} to obtain port.
	 *
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule useApplicationServer() {
		applicationServerPort = 0;
		useApplicationServer = true;
		return this;
	}

	/**
	 * Adds a servlet to the servlet server. Only has an effect when used in
	 * conjunction with {@link #useApplicationServer}.
	 * 
	 * @param servletClass
	 *            the servlet class that should be served.
	 * @param path
	 *            the path on which the servlet should be served, e.g. "/*".
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule addApplicationServlet(Class<? extends Servlet> servletClass, String path) {
		applicationServletsByPath.put(path, new ServletHolder(servletClass));
		return this;
	}

	/**
	 * Adds a servlet to the servlet server. Only has an effect when used in
	 * conjunction with {@link #useApplicationServer}.
	 * 
	 * @param servletHolder
	 *            the servlet inside a {@link ServletHolder} that should be served.
	 * @param path
	 *            the path on which the servlet should be served, e.g. "/*".
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule addApplicationServlet(ServletHolder servletHolder, String path) {
		applicationServletsByPath.put(path, servletHolder);
		return this;
	}

	public SecurityIntegrationTestRule addApplicationServletFilter(Class<? extends Filter> filterClass) {
		applicationServletFilters.add(new FilterHolder(filterClass));
		return this;
	}

	/**
	 * Overwrites the port on which the identity service mock server runs
	 * (WireMock). It needs to be configured before the {@link #before()} method. If
	 * the port is not specified or is set to 0, a free random port is chosen.
	 *
	 * @param port
	 *            the port on which the wire mock service is started.
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule setPort(int port) {
		this.wireMockPort = port;
		return this;
	}

	/**
	 * Overwrites the client id (cid) claim of the token that is being generated. It
	 * needs to be configured before the {@link #before()} method.
	 *
	 * @param clientId
	 *            the port on which the wire mock service is started.
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule setClientId(String clientId) {
		this.clientId = clientId;
		return this;
	}

	/**
	 * Overwrites the private/public key pair to be used. The private key is used to
	 * sign the jwt token. The public key is provided by jwks endpoint (on behalf of
	 * WireMock).
	 * <p>
	 * It needs to be configured before the {@link #before()} method.
	 *
	 * @param keys
	 *            the private/public key pair.
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule setKeys(RSAKeys keys) {
		this.keys = keys;
		return this;
	}

	@Override
	protected void before() throws Exception {
		if (useApplicationServer) {
			startApplicationServer();
		}
		setupWireMock();
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(
				String.format(LOCALHOST_PATTERN, wireMockPort));
		wireMockRule.stubFor(get(urlEqualTo(endpointsProvider.getJwksUri().getPath()))
				.willReturn(aResponse().withBody(createDefaultTokenKeyResponse())));

		switch (service) {
		case XSUAA:
			// prepare endpoints provider
			jwksUrl = endpointsProvider.getJwksUri().toString();
			break;
		default:
			break;
		}

		// starts WireMock (to stub communication to identity service)
	}

	/**
	 * Note: the JwtGenerator is fully configured as part of {@link #before()}
	 * method.
	 *
	 * @return the preconfigured Jwt token generator
	 */
	public JwtGenerator getPreconfiguredJwtGenerator() {
		JwtGenerator jwtGenerator = JwtGenerator.getInstance(service)
				.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, clientId)
				.withPrivateKey(keys.getPrivate())
				.withHeaderParameter(TokenHeader.JWKS_URL, jwksUrl); // TODO null in case of IAS
		return jwtGenerator;
	}

	/**
	 * Creates a very basic token on base of the preconfigured Jwt token generator.
	 * In case you like to specify further token claims, you can make use of
	 * {@link #getPreconfiguredJwtGenerator()}
	 *
	 * @return the token.
	 */
	public Token createToken() {
		return getPreconfiguredJwtGenerator().createToken();
	}

	/**
	 * Allows to stub further endpoints of the identity service. Returns null if the
	 * rule is not yet initialized as part of {@link #before()} method. You can find
	 * a detailed explanation on how to configure wire mock here:
	 * http://wiremock.org/docs/getting-started/
	 */
	@Nullable
	public WireMockRule getWireMockRule() {
		return wireMockRule;
	}

	/**
	 * Returns the URI of the embedded jetty server or null if not specified.
	 */
	@Nullable
	public String getApplicationServerUri() {
		if (useApplicationServer) {
			return String.format(LOCALHOST_PATTERN, applicationServer.getURI().getPort());
		}
		return null;
	}

	private void setupWireMock() {
		if (wireMockPort == 0) {
			wireMockRule = new WireMockRule(options().dynamicPort());
		} else {
			wireMockRule = new WireMockRule(options().port(wireMockPort));
		}
		wireMockRule.start();
		wireMockPort = wireMockRule.port();
	}

	@Override
	protected void after() {
		wireMockRule.shutdown();
		try {
			if (useApplicationServer) {
				applicationServer.stop();
			}
		} catch (Exception e) {
			logger.error("Failed to stop jetty server", e);
		}
	}

	private void startApplicationServer() throws Exception {
		applicationServer = new Server(applicationServerPort);
		ServletHandler servletHandler = createHandlerForServer(applicationServer);
		applicationServletsByPath.forEach((path, servletHolder) -> servletHandler.addServletWithMapping(servletHolder, path));
		applicationServletFilters.forEach((filterHolder) -> servletHandler.addFilterWithMapping(filterHolder, "/*", EnumSet.of(DispatcherType.REQUEST)));
		applicationServer.setHandler(servletHandler);
		applicationServer.start();
	}

	private ServletHandler createHandlerForServer(Server server) {
		ServletHandler servletHandler = new ServletHandler();
		server.setHandler(servletHandler);
		return servletHandler;
	}

	private String createDefaultTokenKeyResponse() throws IOException {
		return IOUtils.resourceToString("/token_keys_template.json", StandardCharsets.UTF_8)
				.replace("$kid", "default-kid")
				.replace("$public_key", Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()));
	}


}
