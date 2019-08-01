package sample.spring.webflux.xsuaa;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sap.cloud.security.xsuaa.token.ReactiveSecurityContext;

import reactor.core.publisher.Mono;

@RestController
public class TestController {

	@GetMapping("/v1/sayHello")
	public Mono<ResponseEntity<String>> sayHello() {
		ResponseEntity.BodyBuilder unAuthenticated = ResponseEntity.status(HttpStatus.UNAUTHORIZED);

		return ReactiveSecurityContext.getToken()
				.doOnError(throwable -> Mono.just(unAuthenticated))
				.map(token -> ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN)
						.body("Authorities: " + token.getAuthorities()));
	}
}
