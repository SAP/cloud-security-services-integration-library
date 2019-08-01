package sample.spring.webflux.xsuaa;

import com.sap.cloud.security.xsuaa.token.ReactiveSecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class TestController {

    @GetMapping("/v1/sayHello")
    public Mono<ResponseEntity<String>> sayHello() {
        ResponseEntity.BodyBuilder unAuthenticated = ResponseEntity.status(HttpStatus.UNAUTHORIZED);

        return ReactiveSecurityContext.getToken()
                .doOnError(throwable -> Mono.just(unAuthenticated))
                .flatMap(token -> {
                    return Mono.just(ResponseEntity.ok()
                            .contentType(MediaType.TEXT_PLAIN)
                            .body("Authorities: " + token.getAuthorities()));
                });
    }
}
