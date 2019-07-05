package com.webflux.xsuaa.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

@RestController
public class ApiController {

	@PostMapping(path = "/v1/demo", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
	public Mono<ResponseEntity<String>> v1Quote(@RequestBody String request) {
		return ReactiveSecurityContextHolder.getContext().flatMap(securityContext -> {
			if (securityContext == null)
				return Mono.just(ResponseEntity.badRequest().contentType(MediaType.APPLICATION_JSON_UTF8)
						.body("{ \"error\": \"error\" }"));

			Authentication authentication = securityContext.getAuthentication();
			Jwt credentials = (Jwt) authentication.getCredentials();
			String tenant = credentials.getClaimAsString("zid");

			return Mono.just(ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON_UTF8)
					.body("{ \"tenant\": \"" + tenant + "\" }"));
		});
	}

}
