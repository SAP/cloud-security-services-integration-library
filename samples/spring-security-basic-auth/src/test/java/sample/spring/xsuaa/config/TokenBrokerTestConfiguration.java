package sample.spring.xsuaa.config;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.springframework.context.annotation.Bean;
import sample.spring.xsuaa.TokenBrokerResolver;

public class TokenBrokerTestConfiguration {

    /** Makes {@link TokenBrokerResolver} use the stubbed XsuaaOAuth2TokenService
     *  prepared in {@link sample.spring.xsuaa.SecurityConfigurationTest} for testing. */
    @Bean
    public XsuaaTokenFlows tokenFlows(XsuaaServiceConfiguration xsuaaConfig, XsuaaOAuth2TokenService tokenService) {
        OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(xsuaaConfig);
        ClientIdentity clientIdentity = xsuaaConfig.getClientIdentity();
        return new XsuaaTokenFlows(tokenService, endpointsProvider, clientIdentity);
    }
}
