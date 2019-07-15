package com.sap.cloud.security.xsuaa.tokenflows;

import java.net.URI;

import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaResourceServerJwkAutoConfiguration;

/**
 * Token decoder interface to provide for 
 * dependency injection of actual token decoder
 * implementation. 
 * 
 * This interface is used to implement a token decoder
 * that can decode tokens from various sources.
 * Since decoding requires the public keys of the token's origin
 * the {@code keySetUri} needs to be specified before decoding.
 * 
 * <b>Note:</b> the standard JwtDecoder exposed as a bean in class 
 * {@link XsuaaResourceServerJwkAutoConfiguration} is referring to 
 * a single Key Set URI, only. This interface defines an API for a
 * JwtDecoder which can be given changing key set URIs.
 */
public interface VariableKeySetUriTokenDecoder extends JwtDecoder {

    /**
     * Sets the JWT Key Set URI.
     * @param keySetUri - the key set URI.
     */
    void setJwksURI(URI keySetUri);
}
