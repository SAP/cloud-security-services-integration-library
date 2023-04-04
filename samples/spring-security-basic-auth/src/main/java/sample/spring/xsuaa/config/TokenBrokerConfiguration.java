package sample.spring.xsuaa.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import sample.spring.xsuaa.security.TokenBrokerResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestOperations;

import java.util.concurrent.TimeUnit;

@Configuration
public class TokenBrokerConfiguration {
    @Bean
    public XsuaaOAuth2TokenService tokenService(@Autowired RestOperations xsuaaMtlsRestOperations) {
        return new XsuaaOAuth2TokenService(xsuaaMtlsRestOperations);
    }

    @Bean(name = "TokenBrokerCache")
    public Cache tokenBrokerCache() {
        return new CaffeineCache("TokenBrokerResolverCache",
                Caffeine.newBuilder().expireAfterWrite(15, TimeUnit.MINUTES).maximumSize(100).build(), false);
    }

    @Bean
    public TokenBrokerResolver tokenBrokerResolver(XsuaaServiceConfiguration xsuaaServiceConfiguration,
                                                   XsuaaOAuth2TokenService tokenService, Cache cache) {
        XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(tokenService,
                new XsuaaDefaultEndpoints(xsuaaServiceConfiguration.getUrl(), xsuaaServiceConfiguration.getCertUrl()),
                xsuaaServiceConfiguration.getClientIdentity());

        return new TokenBrokerResolver(tokenFlows, cache);
    }
}
