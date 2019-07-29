package com.sap.cloud.security.xsuaa.token.flows;

import java.net.URI;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaResourceServerJwkAutoConfiguration;

/**
 * Token decoder interface to provide for dependency injection of actual token
 * decoder implementation.
 * 
 * This interface is used to implement a token decoder that can decode tokens
 * from various sources. Since decoding requires the public keys of the token's
 * origin the {@code keySetUri} needs to be specified before decoding.
 * 
 * <b>Note:</b> the standard JwtDecoder exposed as a bean in class
 * {@link XsuaaResourceServerJwkAutoConfiguration} is referring to a single Key
 * Set URI, only. This interface defines an API for a JwtDecoder which can be
 * given changing key set URIs.
 */
public interface VariableKeySetUriTokenDecoder {

	/**
	 * Sets the JWT Key Set URI.
	 * 
	 * @param keySetUri
	 *            - the key set URI.
	 */
	void setJwksURI(URI keySetUri);

	/**
	 * Decodes the JWT from it's compact claims representation format and returns a
	 * {@link Jwt}.
	 *
	 * @param token
	 *            the JWT value
	 * @return a {@link Jwt}
	 * @throws JwtException
	 *             if an error occurs while attempting to decode the JWT
	 */
	Jwt decode(String token) throws JwtException;
}
