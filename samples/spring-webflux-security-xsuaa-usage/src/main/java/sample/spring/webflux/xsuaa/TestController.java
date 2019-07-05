package sample.spring.webflux.xsuaa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    @GetMapping("/v1/sayHello")
    public Mono<ResponseEntity<String>> sayHello() {
        return ReactiveSecurityContextHolder.getContext().flatMap(securityContext -> {
            if (securityContext == null) {
                return Mono.just(ResponseEntity.badRequest().contentType(MediaType.APPLICATION_JSON_UTF8)
                        .body("{ \"error\": \"error\" }"));
            }
            Authentication authentication = securityContext.getAuthentication();
            Jwt credentials = (Jwt) authentication.getCredentials();
            logger.info("Got the Jwt token: " + credentials.getTokenValue());

            return Mono.just(ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN)
                    .body("" + credentials.getClaims()));
        });
    }
}
