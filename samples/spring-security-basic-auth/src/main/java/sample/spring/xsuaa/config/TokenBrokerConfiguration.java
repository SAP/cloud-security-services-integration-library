package sample.spring.xsuaa.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import sample.spring.xsuaa.security.TokenBrokerResolver;

import java.util.concurrent.TimeUnit;

@Configuration
public class TokenBrokerConfiguration {

    @Bean(name = "TokenBrokerCache")
    public Cache tokenBrokerCache() {
        return new CaffeineCache("TokenBrokerResolverCache",
                Caffeine.newBuilder().expireAfterWrite(15, TimeUnit.MINUTES).maximumSize(100).build(), false);
    }

    @Bean
    public TokenBrokerResolver tokenBrokerResolver(XsuaaTokenFlows tokenFlows, Cache cache) {
        return new TokenBrokerResolver(tokenFlows, cache);
    }
}
