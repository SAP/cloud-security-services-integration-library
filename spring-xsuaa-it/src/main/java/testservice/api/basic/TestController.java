/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package testservice.api.basic;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.junit.Assert.assertThat;

import java.net.URISyntaxException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sap.cloud.security.xsuaa.token.Token;
import com.sap.xs2.security.container.XSTokenRequestImpl;
import com.sap.xsa.security.container.XSTokenRequest;

@RestController
public class TestController {

	@Value("${mockxsuaaserver.url}")
	String mockServerUrl;

	@GetMapping("/")
	public String index(@AuthenticationPrincipal Jwt jwt) {
		return String.format("Hello, %s!", jwt.getSubject());
	}

	@GetMapping("/user")
	public String message(@AuthenticationPrincipal Token token) {
		return token.getUsername();
	}

	@GetMapping("/scope")
	public void checkScope(@AuthenticationPrincipal Token token) {
		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) token.getAuthorities();
		assertThat(authorities.size(), is(4));
		assertThat(authorities, hasItem(new SimpleGrantedAuthority("openid")));
		assertThat(authorities, hasItem(new SimpleGrantedAuthority("java-hello-world.Display")));
		assertThat(authorities, not(hasItem(new SimpleGrantedAuthority("java-hello-world.Other"))));
	}

	@GetMapping("/requesttoken")
	public String requestToken(@AuthenticationPrincipal Token token) throws URISyntaxException {
		XSTokenRequestImpl tokenRequest = new XSTokenRequestImpl(mockServerUrl);
		tokenRequest.setClientId("c1").setClientSecret("s1").setType(XSTokenRequest.TYPE_CLIENT_CREDENTIALS_TOKEN);
		Map<String, String> azMape = new HashMap<>();
		azMape.put("a", "b");
		azMape.put("c", "d");
		tokenRequest.setAdditionalAuthorizationAttributes(azMape);
		String newToken = token.requestToken(tokenRequest);
		return newToken;
	}
}
