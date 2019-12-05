package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.servlet.OAuth2SecurityFilter;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.http.MediaType;
import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.rules.ExternalResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.DispatcherType;
import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

public class SecurityIntegrationTestRule extends ExternalResource {

	private static final Logger logger = LoggerFactory.getLogger(SecurityIntegrationTestRule.class);
	private static final String LOCALHOST_PATTERN = "http://localhost:%d";

	private RSAKeys keys;

	private int jwksServerPort = 0;
	private Server jwksServer;
	private URI jwksUrl;

	private boolean useServletServer;
	private int servletServerPort = 0;
	private Server servletServer;
	private Map<String, Class<? extends Servlet>> servletsByPathSpec = new HashMap<>();

	private Service service;
	private String clientId;

	private SecurityIntegrationTestRule() {
		// see factory method getInstance()
	}

	public static SecurityIntegrationTestRule getInstance(Service service) {
		SecurityIntegrationTestRule instance = new SecurityIntegrationTestRule();
		instance.keys = RSAKeys.generate();
		instance.service = service;
		return instance;
	}

	/**
	 * Specifies an embedded jetty as servlet server. It needs to be configured
	 * before the {@link #before()} method. If the port is set to 0, a free
	 * random port is chosen.
	 *
	 * @param port
	 *            the port on which the application service is started.
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule useServletServer(int port) {
		servletServerPort = port;
		useServletServer = true;
		return this;
	}

	/**
	 * Adds a servlet to the servlet server. Only has an effect when used in conjunction
	 * with {@link #useServletServer}.
	 * @param servletClass the servlet class that should be served.
	 * @param pathSpec the path on which the servlet should be served, e.g. "/*".
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule addServlet(Class<? extends Servlet> servletClass, String pathSpec) {
		servletsByPathSpec.put(pathSpec, servletClass);
		return this;
	}

	/**
	 * Overwrites the port on which the jwks mock server runs. It needs to be
	 * configured before the {@link #before()} method. If the port is not specified
	 * or is set to 0, a free random port is chosen.
	 *
	 * @param port
	 *            the port on which the wire mock service is started.
	 * @return the rule itself.
	 */
	public SecurityIntegrationTestRule setPort(int port) {
		this.jwksServerPort = port;
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
		jwksServer = new Server(jwksServerPort);
		ServletHandler jwksServerServletHandler = createHandlerForServer(jwksServer);
		jwksServer.start();
		if (useServletServer) {
			startServletServer();
		}
		switch (service) {
		case XSUAA:
			// prepare endpoints provider
			XsuaaDefaultEndpoints endpointsProvider = new XsuaaDefaultEndpoints(
					String.format(LOCALHOST_PATTERN, jwksServer.getURI().getPort()));
			jwksUrl = endpointsProvider.getJwksUri();
			break;
		default:
			throw new UnsupportedOperationException("Service " + service + " is not yet supported.");
		}

		ServletHolder servletHolder = new ServletHolder(new JwksServlet());
		jwksServerServletHandler.addServletWithMapping(servletHolder, jwksUrl.getPath());
	}

	/**
	 * Note: the JwtGenerator is fully configured as part of {@link #before()}
	 * method.
	 *
	 * @return the preconfigured Jwt token generator
	 */
	public JwtGenerator getPreconfiguredJwtGenerator() {
		return JwtGenerator.getInstance(service)
				.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, clientId)
				.withPrivateKey(keys.getPrivate())
				.withHeaderParameter(TokenHeader.JWKS_URL, jwksUrl.toString());
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
	 * Returns the URI of the embedded jetty server or null if not specified.
	 */
	@Nullable
	public String getServletServerUri() {
		if (useServletServer) {
			return String.format(LOCALHOST_PATTERN, servletServer.getURI().getPort());
		}
		return null;
	}

	@Override
	protected void after() {
		try {
			jwksServer.stop();
			if (useServletServer) {
				servletServer.stop();
			}
		} catch (Exception e) {
			logger.error("Failed to stop jetty server", e);
		}
	}


	private void startServletServer() throws Exception {
		servletServer = new Server(servletServerPort);
		ServletHandler servletHandler = createHandlerForServer(servletServer);
		servletsByPathSpec.forEach((pathSpec, servlet) -> servletHandler.addServletWithMapping(servlet, pathSpec));
		servletHandler.addFilterWithMapping(OAuth2SecurityFilter.class, "/*", EnumSet.of(DispatcherType.REQUEST));
		servletServer.setHandler(servletHandler);
		servletServer.start();
	}

	private ServletHandler createHandlerForServer(Server server)  {
		ServletHandler jwksServerServletHandler = new ServletHandler();
		server.setHandler(jwksServerServletHandler);
		return jwksServerServletHandler;
	}

	private class JwksServlet extends HttpServlet {
		@Override
		protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
			response.setStatus(HttpServletResponse.SC_OK);
			response.setContentType(MediaType.APPLICATION_JSON.value());
			response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
			response.getWriter().write(createDefaultTokenKeyResponse());
		}
	}

	private String createDefaultTokenKeyResponse() throws IOException {
		return IOUtils.resourceToString("/token_keys_template.json", StandardCharsets.UTF_8)
				.replace("$kid", "default-kid")
				.replace("$public_key", Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()));
	}

}
