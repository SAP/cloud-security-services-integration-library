package com.sap.cloud.security.test;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.jetty.JettyTokenAuthenticator;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.annotations.AnnotationConfiguration;
import org.eclipse.jetty.plus.webapp.EnvConfiguration;
import org.eclipse.jetty.plus.webapp.PlusConfiguration;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.webapp.*;
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
import static com.sap.cloud.security.xsuaa.client.OidcConfigurationService.DISCOVERY_ENDPOINT_DEFAULT;

public class SecurityIntegrationTestRule extends ExternalResource {

	private static final Logger logger = LoggerFactory.getLogger(SecurityIntegrationTestRule.class);
	private static final String LOCALHOST_PATTERN = "http://localhost:%d";
	private final Map<String, ServletHolder> applicationServletsByPath = new HashMap<>();
	private final List<FilterHolder> applicationServletFilters = new ArrayList<>();
	// app server
	private Server applicationServer;
	private ApplicationServerOptions applicationServerOptions;
	private boolean useApplicationServer;

	// mock server
	private WireMockRule wireMockRule;
	private RSAKeys keys;
	private int wireMockPort = 0;
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
		instance.keys = RSAKeys.generate();
		instance.service = service;
		ApplicationServerOptions.createOptionsForService(service);
		return instance;
	}

	/**
	 * Specifies an embedded jetty as servlet server. It needs to be configured
	 * before the {@link #before()} method. The application server will be started
	 * with default options for the given {@link Service},
	 * see {@link ApplicationServerOptions#createOptionsForService(Service)} for
	 * details. By default the servlet server will listen on a free random port.
	 * Use
	 * {@link SecurityIntegrationTestRule#useApplicationServer(ApplicationServerOptions)}
	 * to overwrite default settings. Use {@link #getApplicationServerUri()} to
	 * obtain the actual port used at runtime.
	 *
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule useApplicationServer() {
		return useApplicationServer(ApplicationServerOptions.createOptionsForService(service));
	}

	/**
	 * Specifies an embedded jetty as servlet server. It needs to be configured
	 * before the {@link #before()} method. Use
	 * {@link ApplicationServerOptions#createOptionsForService(Service)} to obtain a
	 * configuration object that can be customized. See
	 * {@link ApplicationServerOptions} for details.
	 *
	 * @param applicationServerOptions
	 *            custom options to configure the application server.
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule useApplicationServer(ApplicationServerOptions applicationServerOptions) {
		this.applicationServerOptions = applicationServerOptions;
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
				.withPrivateKey(keys.getPrivate());
		switch (service) {
		case XSUAA:
			jwtGenerator.withHeaderParameter(TokenHeader.JWKS_URL, jwksUrl);
			break;
		default:
			jwtGenerator.withClaimValue(TokenClaims.ISSUER, wireMockRule.baseUrl());
			break;
		}

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

	private void setupWireMock() throws IOException {
		if (wireMockPort == 0) {
			wireMockRule = new WireMockRule(options().dynamicPort());
		} else {
			wireMockRule = new WireMockRule(options().port(wireMockPort));
		}
		wireMockRule.start();
		wireMockPort = wireMockRule.port();

		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(
				String.format(LOCALHOST_PATTERN, wireMockPort));
		wireMockRule.stubFor(get(urlEqualTo(endpointsProvider.getJwksUri().getPath()))
				.willReturn(aResponse().withBody(createDefaultTokenKeyResponse())));
		wireMockRule.stubFor(get(urlEqualTo(DISCOVERY_ENDPOINT_DEFAULT))
				.willReturn(aResponse().withBody(createDefaultOidcConfigurationResponse())));
		jwksUrl = endpointsProvider.getJwksUri().toString();
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
		WebAppContext context = createWebAppContext();
		ServletHandler servletHandler = createServletHandler(context);

		applicationServletsByPath
				.forEach((path, servletHolder) -> servletHandler.addServletWithMapping(servletHolder, path));
		applicationServletFilters.forEach((filterHolder) -> servletHandler
				.addFilterWithMapping(filterHolder, "/*", EnumSet.of(DispatcherType.REQUEST)));

		applicationServer = new Server(applicationServerOptions.getPort());
		applicationServer.setHandler(context);
		applicationServer.start();
	}

	private ServletHandler createServletHandler(WebAppContext context) {
		ConstraintSecurityHandler security = new ConstraintSecurityHandler();
		JettyTokenAuthenticator authenticator = new JettyTokenAuthenticator(
				applicationServerOptions.getTokenAuthenticator());
		security.setAuthenticator(authenticator);
		ServletHandler servletHandler = new ServletHandler();
		security.setHandler(servletHandler);
		context.setServletHandler(servletHandler);
		context.setSecurityHandler(security);
		return servletHandler;
	}

	private WebAppContext createWebAppContext() {
		WebAppContext context = new WebAppContext();
		context.setConfigurations(new Configuration[] {
				new AnnotationConfiguration(), new WebXmlConfiguration(),
				new WebInfConfiguration(), new PlusConfiguration(), new MetaInfConfiguration(),
				new FragmentConfiguration(), new EnvConfiguration() });
		context.setContextPath("/");
		context.setResourceBase("src/main/java/webapp");
		context.setParentLoaderPriority(true);
		return context;
	}

	private String createDefaultTokenKeyResponse() throws IOException {
		return IOUtils.resourceToString("/token_keys_template.json", StandardCharsets.UTF_8)
				.replace("$kid", "default-kid")
				.replace("$public_key", Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()));
	}

	private String createDefaultOidcConfigurationResponse() throws IOException {
		return IOUtils.resourceToString("/oidcConfigurationTemplate.json", StandardCharsets.UTF_8)
				.replace("$issuer", wireMockRule.baseUrl());
	}

}
