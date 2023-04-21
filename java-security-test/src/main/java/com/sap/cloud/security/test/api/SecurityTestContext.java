/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.api;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.Token;

import javax.annotation.Nullable;

public interface SecurityTestContext {

	/**
	 * This creates a JwtGenerator is fully configured as part of the {@code setup}
	 * method so that it can be used for testing.
	 *
	 * @return the preconfigured Jwt token generator
	 */
	JwtGenerator getPreconfiguredJwtGenerator();

	/**
	 * This method creates an JwtGenerator that uses
	 * {@link JwtGenerator#getInstanceFromFile(Service, String)} to provide a
	 * {@link JwtGenerator} prefilled data contained in the
	 * {@code tokenJsonResource} file. Some properties are overridden so that the
	 * generated tokens can be used in unit tests.
	 *
	 * @param tokenJsonResource
	 *            the resource path to the file containing the json file, see
	 *            {@link JwtGenerator#getInstanceFromFile(Service, String)}
	 * @return a new {@link JwtGenerator} instance
	 * @throws IllegalArgumentException
	 *             if the resource cannot be read
	 * @throws JsonParsingException
	 *             if the file contains invalid data
	 */
	JwtGenerator getJwtGeneratorFromFile(String tokenJsonResource);

	/**
	 * Creates a {@link OAuth2ServiceConfigurationBuilder} prefilled with the data
	 * from the classpath resource given by {@code configurationResourceName}. The
	 * {@code url} of the configuration will be overridden with the url of the mock
	 * server.
	 *
	 * @param configurationResourceName
	 *            the name of classpath resource that contains the configuration
	 *            json
	 * @return a new {@link OAuth2ServiceConfigurationBuilder} instance
	 * @throws IllegalArgumentException
	 *             if the resource cannot be read
	 * @throws JsonParsingException
	 *             if the resource contains invalid data
	 */
	OAuth2ServiceConfigurationBuilder getOAuth2ServiceConfigurationBuilderFromFile(String configurationResourceName);

	/**
	 * Creates a very basic token on base of the preconfigured Jwt token generator.
	 * In case you like to specify further token claims, you can make use of
	 * {@link #getPreconfiguredJwtGenerator()}
	 *
	 * @return the token.
	 */
	Token createToken();

	/**
	 * Allows to stub further endpoints of the identity service. You can find a
	 * detailed explanation on how to configure wire mock here:
	 * <a href="http://wiremock.org/docs/getting-started/">http://wiremock.org/docs/getting-started/</a>
	 *
	 * @return an instance of WireMockServer
	 */
	WireMockServer getWireMockServer();

	/**
	 * Returns the URI of the embedded jetty server or null if it has not been
	 * activated.
	 *
	 * @return uri of the application server
	 */
	@Nullable
	String getApplicationServerUri();
}
