/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceBindingMapper;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.test.api.ApplicationServerConfiguration;
import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.api.ServiceMockConfiguration;
import com.sap.cloud.security.test.jetty.JettyTokenAuthenticator;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.MediaType;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.Servlet;
import org.apache.commons.io.IOUtils;
import org.eclipse.jetty.ee9.security.ConstraintSecurityHandler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.ee9.servlet.FilterHolder;
import org.eclipse.jetty.ee9.servlet.ServletHolder;
import org.eclipse.jetty.ee9.webapp.WebAppContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.xsuaa.client.OidcConfigurationService.DISCOVERY_ENDPOINT_DEFAULT;

public class SecurityTest
		implements SecurityTestContext, ServiceMockConfiguration, ApplicationServerConfiguration {

	protected static final Logger LOGGER = LoggerFactory.getLogger(SecurityTest.class);

	// DEFAULTS
	public static final String DEFAULT_APP_ID = "xsapp!t0815";
	public static final String DEFAULT_CLIENT_ID = "sb-clientId!t0815";
	public static final String DEFAULT_DOMAIN = "localhost";
	public static final String DEFAULT_UAA_DOMAIN = "http://localhost";
	public static final String DEFAULT_URL = "http://localhost";

	protected static final String LOCALHOST_PATTERN = "http://localhost:%d";

	protected final Map<String, ServletHolder> applicationServletsByPath = new HashMap<>();
	protected final List<FilterHolder> applicationServletFilters = new ArrayList<>();
	// app server
	protected Server applicationServer;
	protected ApplicationServerOptions applicationServerOptions;
	protected boolean useApplicationServer;

	// mock server
	protected WireMockServer wireMockServer;
	protected RSAKeys keys;
	protected final Service service;

	protected static final String clientId = DEFAULT_CLIENT_ID;
	protected String jwksUrl;
	private String issuerUrl;

	public SecurityTest(Service service) {
		this.service = service;
		this.keys = RSAKeys.generate();
		this.wireMockServer = new WireMockServer(options().dynamicPort());
	}

	@Override
	public SecurityTest useApplicationServer() {
		this.useApplicationServer = true;
		return this;
	}

	@Override
	public SecurityTest useApplicationServer(ApplicationServerOptions applicationServerOptions) {
		this.applicationServerOptions = applicationServerOptions;
		this.useApplicationServer = true;
		return this;
	}

	@Override
	public SecurityTest addApplicationServlet(Class<? extends Servlet> servletClass, String path) {
		applicationServletsByPath.put(path, new ServletHolder(servletClass));
		return this;
	}

	@Override
	public SecurityTest addApplicationServlet(ServletHolder servletHolder, String path) {
		applicationServletsByPath.put(path, servletHolder);
		return this;
	}

	@Override
	public SecurityTest addApplicationServletFilter(Class<? extends Filter> filterClass) {
		applicationServletFilters.add(new FilterHolder(filterClass));
		return this;
	}

	@Override
	public SecurityTest setPort(int port) {
		wireMockServer = new WireMockServer(options().port(port));
		return this;
	}

	@Override
	public SecurityTest setKeys(String publicKeyPath, String privateKeyPath) {
		try {
			this.keys = RSAKeys.fromKeyFiles(publicKeyPath, privateKeyPath);
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new UnsupportedOperationException(e);
		}
		return this;
	}

	@Override
	public JwtGenerator getPreconfiguredJwtGenerator() {
		JwtGenerator jwtGenerator = JwtGenerator.getInstance(service, clientId).withPrivateKey(keys.getPrivate());

		if (jwksUrl == null || issuerUrl == null) {
			LOGGER.warn("Method getPreconfiguredJwtGenerator was called too soon. Cannot set mock jwks/issuer url!");
		}

		if (XSUAA.equals(service)) {
			jwtGenerator
					.withHeaderParameter(TokenHeader.JWKS_URL, jwksUrl)
					.withAppId(DEFAULT_APP_ID)
					.withClaimValue(TokenClaims.XSUAA.GRANT_TYPE, OAuth2TokenServiceConstants.GRANT_TYPE_JWT_BEARER);
		}

		return jwtGenerator.withClaimValue(TokenClaims.ISSUER, issuerUrl);
	}

	@Override
	public JwtGenerator getJwtGeneratorFromFile(String tokenJsonResource) {
		JwtGenerator jwtGenerator = JwtGenerator.getInstanceFromFile(service, tokenJsonResource)
				.withClaimValue(TokenClaims.ISSUER, issuerUrl)
				.withPrivateKey(keys.getPrivate());
		if (XSUAA == service) {
			jwtGenerator.withHeaderParameter(TokenHeader.JWKS_URL, jwksUrl);
		}
		return jwtGenerator;
	}

	@Override
	public OAuth2ServiceConfigurationBuilder getOAuth2ServiceConfigurationBuilderFromFile(
			String configurationResourceName) {
		String vcapJson;
		try {
			vcapJson = IOUtils.resourceToString(configurationResourceName, StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new IllegalArgumentException("Error reading configuration file: " + e.getMessage());
		}

		List<ServiceBinding> serviceBindings = new SapVcapServicesServiceBindingAccessor(any -> vcapJson)
				.getServiceBindings().stream()
				// extract only service bindings for supported OAuth2 services from JSON
				.filter(b -> b.getServiceName().isPresent() && Service.from(b.getServiceName().get()) != null)
				.limit(2)
				.toList();

		if (serviceBindings.isEmpty()) {
			throw new JsonParsingException("No supported binding found in VCAP_SERVICES!");
		} else if (serviceBindings.size() > 1) {
			LOGGER.warn("More than one OAuth2 service binding found in resource. Using configuration of first one!");
		}

		ServiceBinding binding = serviceBindings.get(0);
		OAuth2ServiceConfigurationBuilder builder = ServiceBindingMapper.mapToOAuth2ServiceConfigurationBuilder(binding);
		if (builder != null) {
			// adjust domain and URL of the config to fit the mocked service instance
			builder = builder.withDomains(URI.create(issuerUrl).getHost()).withUrl(issuerUrl);

			if(Objects.equals(Service.from(binding.getServiceName().get()), XSUAA)) {
				builder.withProperty(ServiceConstants.XSUAA.UAA_DOMAIN, wireMockServer.baseUrl());
			}
		}

		return builder;
	}

	@Override
	public Token createToken() {
		return getPreconfiguredJwtGenerator().createToken();
	}

	@Override
	public WireMockServer getWireMockServer() {
		return wireMockServer;
	}

	@Override
	@Nullable
	public String getApplicationServerUri() {
		if (useApplicationServer) {
			return String.format(LOCALHOST_PATTERN, applicationServer.getURI().getPort());
		}
		return null;
	}

	void startApplicationServer() throws Exception {
		ConstraintSecurityHandler security = new ConstraintSecurityHandler();
		JettyTokenAuthenticator authenticator = new JettyTokenAuthenticator(
				applicationServerOptions.getTokenAuthenticator());
		security.setAuthenticator(authenticator);

		WebAppContext context = new WebAppContext();
		context.setContextPath("/");
		context.setResourceBase("src/main/webapp");
		context.setSecurityHandler(security);

		applicationServletsByPath
				.forEach((path, servletHolder) -> context.addServlet(servletHolder, path));
		applicationServletFilters.forEach(filterHolder -> context
				.addFilter(filterHolder, "/*", EnumSet.of(DispatcherType.REQUEST)));

		context.addFilter(new FilterHolder(new SecurityFilter()), "/*", EnumSet.of(DispatcherType.REQUEST));

		applicationServer = new Server(applicationServerOptions.getPort());
		applicationServer.setHandler(context);
		applicationServer.start();
	}

	String createDefaultTokenKeyResponse() throws IOException {
		String encodedPublicKeyModulus = Base64.getUrlEncoder()
				.encodeToString(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
		String encodedPublicKey = Base64.getEncoder().encodeToString(keys.getPublic().getEncoded());
		return IOUtils.resourceToString("/token_keys_template.json", StandardCharsets.UTF_8)
				.replace("$kid", getKeyId())
				.replace("$public_key", encodedPublicKey)
				.replace("$modulus", encodedPublicKeyModulus);
	}

	private String getKeyId() {
		return this.service == IAS ? JwtGenerator.DEFAULT_KEY_ID_IAS : JwtGenerator.DEFAULT_KEY_ID;
	}

	String createDefaultOidcConfigurationResponse() throws IOException {
		return IOUtils.resourceToString("/oidcConfigurationTemplate.json", StandardCharsets.UTF_8)
				.replace("$issuer", wireMockServer.baseUrl());
	}

	/**
	 * Starts the Jetty application web server and the WireMock OAuthServer if not
	 * running. Otherwise it resets WireMock and configures the stubs. Additionally
	 * it generates the JWK URL. Should be called before each test. Starts the
	 * server only, if it was not yet started.
	 *
	 * @throws IOException
	 *             if the stub cannot be initialized
	 */
	public void setup() throws Exception {
		if (!wireMockServer.isRunning()) {
			wireMockServer.start();
		} else {
			wireMockServer.resetAll();
		}
		if (useApplicationServer && (applicationServer == null || !applicationServer.isStarted())) {
			if (applicationServerOptions == null){
				this.applicationServerOptions = ApplicationServerOptions.forService(service, wireMockServer.port());
			}
			startApplicationServer();
		}
		// TODO return JSON Media type
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(
				String.format(LOCALHOST_PATTERN, wireMockServer.port()), null);
		wireMockServer.stubFor(get(urlPathEqualTo(endpointsProvider.getJwksUri().getPath()))
				.willReturn(aResponse().withBody(createDefaultTokenKeyResponse())
						.withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.value())));
		wireMockServer.stubFor(get(urlEqualTo(DISCOVERY_ENDPOINT_DEFAULT))
				.willReturn(aResponse().withBody(createDefaultOidcConfigurationResponse())
						.withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.value())));
		jwksUrl = endpointsProvider.getJwksUri().toString();
		issuerUrl = wireMockServer.baseUrl();
	}

	/**
	 * Shuts down Jetty application web server and WireMock stub. Should be called
	 * when all tests are executed to avoid unwanted side-effects.
	 */
	public void tearDown() {
		shutdownWireMock();
		try {
			if (useApplicationServer) {
				applicationServer.stop();
			}
		} catch (Exception e) {
			LOGGER.error("Failed to stop jetty server", e);
		}
	}

	/**
	 * The {@code shutdown} method of WireMock does not block the main thread. This
	 * can cause issues if one static {@link SecurityTestRule} is reused in many
	 * test classes. Therefore we wait until the WireMock server has really been
	 * shutdown (or the maximum amount of tries has been reached).
	 */
	private void shutdownWireMock() {
		wireMockServer.shutdown();
		int maxTries = 100;
		for (int tries = 0; tries < maxTries && wireMockServer.isRunning(); tries++) {
			try {
				Thread.sleep(50);
			} catch (InterruptedException e) {
				LOGGER.warn("Got interrupted while waiting for WireMock to shutdown. Giving up!");
				Thread.currentThread().interrupt(); // restore the interrupted status
				break; // stop blocking
			}
		}
	}
}
