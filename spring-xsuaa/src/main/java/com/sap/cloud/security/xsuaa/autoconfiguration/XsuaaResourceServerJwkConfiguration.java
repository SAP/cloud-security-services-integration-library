package com.sap.cloud.security.xsuaa.autoconfiguration;

import java.io.File;
import java.io.IOException;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnResource;
import org.springframework.boot.autoconfigure.security.oauth2.resource.IssuerUriCondition;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.util.Assert;

import com.sap.cloud.security.xsuaa.DefaultXsuaaServiceBindings;
import com.sap.cloud.security.xsuaa.XsuaaAudienceValidator;
import com.sap.cloud.security.xsuaa.XsuaaServiceBindings;

// Copied from org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerJwkConfiguration
// Unfortunately there is (today) no better way to get the default configurations for Validators of Spring Security.

/**
 * Auto-configuration class that exposes a JwtDecoder which has the standard
 * Spring Security Jwt validators as well as the XSUAA-specific validators.
 * @See: org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerJwkConfiguration
 */

// This is what we would prefer but OAuth2ResourceServerJwtConfiguration 
// is not a public class. :(
//@AutoConfigureBefore(OAuth2ResourceServerJwtConfiguration.class)

// Instead we will add ourselves before OAuth2ResourceServerAutoConfiguration.
// OAuth2ResourceServerAutoConfiguration will be evaluated before 
// OAuth2ResourceServerJwtConfiguration which exposes the JwtDecoder.
// And since we want to expose our own one, we add ourselves before.

@Configuration
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration.class)
@ConditionalOnClass(OAuth2ResourceServerProperties.class)
public class XsuaaResourceServerJwkConfiguration {

    private final OAuth2ResourceServerProperties properties;

    public XsuaaResourceServerJwkConfiguration(OAuth2ResourceServerProperties properties) {
        Assert.notNull(properties, "Properties must not be null.");
        this.properties = properties;
    }

    @Bean
    @ConditionalOnProperty(name = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri")
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoderByJwkKeySetUri(XsuaaServiceBindings xsuaaServiceBindings) {
        String jwkSetUri = this.properties.getJwt().getJwkSetUri();
        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefault();
        OAuth2TokenValidator<Jwt> xsuaaAudienceValidator = new XsuaaAudienceValidator(xsuaaServiceBindings);
        OAuth2TokenValidator<Jwt> combinedValidators = new DelegatingOAuth2TokenValidator<>(defaultValidators, xsuaaAudienceValidator);
        NimbusJwtDecoderJwkSupport jwtDecoder = new NimbusJwtDecoderJwkSupport(jwkSetUri);
        jwtDecoder.setJwtValidator(combinedValidators);
        return jwtDecoder;
    }

    @Bean
    @Conditional(IssuerUriCondition.class)
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoderByIssuerUri(XsuaaServiceBindings xsuaaServiceBindings) {
        String oidcIssuerLocation = this.properties.getJwt().getIssuerUri();
        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefaultWithIssuer(oidcIssuerLocation);
        OAuth2TokenValidator<Jwt> xsuaaAudienceValidator = new XsuaaAudienceValidator(xsuaaServiceBindings);
        OAuth2TokenValidator<Jwt> combinedValidators = new DelegatingOAuth2TokenValidator<>(defaultValidators, xsuaaAudienceValidator);
        NimbusJwtDecoderJwkSupport jwtDecoder = (NimbusJwtDecoderJwkSupport) JwtDecoders.fromOidcIssuerLocation(oidcIssuerLocation);
        jwtDecoder.setJwtValidator(combinedValidators);
        return jwtDecoder;
    }
    
    @Bean
    @ConditionalOnMissingBean
    @Conditional(MissingVcapServicesFileCondition.class)
    public XsuaaServiceBindings xsuaaServiceBindings(Environment environment) {
        return new DefaultXsuaaServiceBindings(environment);
    }
    
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnResource(resources = {"vcap-services.json"})
    public XsuaaServiceBindings xsuaaServiceBindingsFromFile() throws IOException {
        File vcapFile = new ClassPathResource("vcap-services.json").getFile();
        return new DefaultXsuaaServiceBindings(vcapFile);
    }
    
    public static class MissingVcapServicesFileCondition implements Condition {

        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            return !context.getResourceLoader().getResource("vcap-services.json").exists();
        }
    }
}
