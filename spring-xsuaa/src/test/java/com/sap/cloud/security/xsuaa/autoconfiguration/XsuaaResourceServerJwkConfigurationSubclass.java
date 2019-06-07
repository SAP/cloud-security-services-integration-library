package com.sap.cloud.security.xsuaa.autoconfiguration;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;

@TestConfiguration
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration.class)
@ConditionalOnClass(OAuth2ResourceServerProperties.class)
public class XsuaaResourceServerJwkConfigurationSubclass extends XsuaaResourceServerJwkConfiguration {


    public XsuaaResourceServerJwkConfigurationSubclass(OAuth2ResourceServerProperties properties) {
        super(properties);
    }
    
    /* 
     * "Mock" implementation returning a NimbusJwtDecoderJwkSupport which does not make a network
     * call to resolve the OIDC issuer endpoint, but uses a jwkSetUri instead.
     */
    @Override
    protected NimbusJwtDecoderJwkSupport nimbusJwtDecoderFromOidcIssuerLocation(String jwkSetUri) {
        return new NimbusJwtDecoderJwkSupport(jwkSetUri);
    }    
}
