package com.sap.cloud.security.xsuaa.client;

import javax.annotation.Nonnull;

import java.net.URI;


@SuppressWarnings("squid:S1214")
public interface OidcConfigurationService {
	String DISCOVERY_ENDPOINT_DEFAULT = "/.well-known/openid-configuration"; //NOSONAR


	/**
	 * Requests an OpenID Provider Configuration Document from OAuth Server.
	 *
	 * @param discoveryEndpointUri
	 *            the discovery endpoint URI.
	 * @return an object with access endpoints.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	OAuth2ServiceEndpointsProvider retrieveEndpoints(@Nonnull URI discoveryEndpointUri) throws OAuth2ServiceException;

	/**
	 * Requests an OpenID Provider Configuration Document from OAuth Server.
	 *
	 * @param issuerUri that contains the protocol and host of the issuer,
	 *                  which will be enhanced with ".well-known/openid-configuration".
	 * @return an object with access endpoints.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	OAuth2ServiceEndpointsProvider retrieveIssuerEndpoints(@Nonnull URI issuerUri) throws OAuth2ServiceException;
}
