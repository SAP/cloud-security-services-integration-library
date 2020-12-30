package com.sap.cloud.security.authentication;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.servlet.HybridJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;


public class JwtDecoderBuilder {

    /**
     * Utility for building a JWT decoder configuration
     *
     * @param configuration of the Xsuaa service
     */
    public JwtDecoderBuilder(OAuth2ServiceConfiguration configuration, String iasClientId) {

    }

    /**
     * Assembles a JwtDecoder
     *
     * @return JwtDecoder
     */
    public JwtDecoder buildHybrid() {
        return new HybridJwtDecoder();
    }
}
