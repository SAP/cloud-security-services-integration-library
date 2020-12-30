package com.sap.cloud.security.authentication;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.springframework.security.oauth2.jwt.JwtDecoder;


public class HybridJwtDecoderBuilder {

    /**
     * Utility for building a JWT decoder configuration
     *
     * @param configuration of the Xsuaa service
     */
    public HybridJwtDecoderBuilder(OAuth2ServiceConfiguration configuration, String iasClientId) {

    }

    /**
     * Assembles a JwtDecoder
     *
     * @return JwtDecoder
     */
    public JwtDecoder build() {
        // create XsuaaJwtDecoder via builder and create HybridJwtDecoder that wraps an ias oidc decoder
        return null;
    }
}
