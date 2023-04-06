package sample.spring.xsuaa.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import sample.spring.xsuaa.TokenBrokerResolver;

import java.util.concurrent.TimeUnit;

@Configuration
public class TokenBrokerConfiguration {

    @Bean
    public Cache tokenBrokerCache() {
        return new CaffeineCache("TokenBrokerResolverCache",
                Caffeine.newBuilder().expireAfterWrite(15, TimeUnit.MINUTES).maximumSize(100).build(), false);
    }

    /** Configures a TokenBrokerResolver with the default XsuaaTokenFlows and the specific cache configured for it. */
    @Bean
    public TokenBrokerResolver tokenBrokerResolver(XsuaaTokenFlows tokenFlows, @Qualifier("tokenBrokerCache") Cache cache) {
        return new TokenBrokerResolver(tokenFlows, cache);
    }
}
