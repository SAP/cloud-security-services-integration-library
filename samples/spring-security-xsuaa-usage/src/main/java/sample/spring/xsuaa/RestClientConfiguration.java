package sample.spring.xsuaa;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestClientConfiguration {

    @Bean
    RestTemplate myRestTemplate() {
        return new RestTemplate();
    }

    @Bean
    RestTemplate xsuaaRestOperations() {
        return new RestTemplate();
    }

}
