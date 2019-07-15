package com.sap.cloud.security.xsuaa.tokenflows;

import java.net.URI;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Token decoder interface to provide for 
 * dependency injection of actual token decoder
 * implementation. 
 * 
 * This interface is used to implement a token decoder
 * that can decode tokens from various sources.
 * Since decoding requires the public keys of the token's origin
 * the {@code keySetUri} needs to be specified before decoding.
 */
public interface TokenDecoder {

    /**
     * Sets the JWT Key Set URI.
     * @param keySetUri - the key set URI.
     */
    void setJwksURI(URI keySetUri);
    
    /**
     * Decodes the given String value into an OAuth2 JWT token.
     * @param encodedValue - the encoded JWT token.
     * @return the decoded OAuth2 JWT token.
     */
    Jwt decode(String encodedValue);
}
