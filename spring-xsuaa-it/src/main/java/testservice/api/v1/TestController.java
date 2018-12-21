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
package testservice.api.v1;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

import java.net.URISyntaxException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
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
		// attributes - old style
		Assert.assertEquals(2, token.getXSUserAttribute("cost-center").length);
		Assert.assertEquals("0815", token.getXSUserAttribute("cost-center")[0]);
		Assert.assertEquals("4711", token.getXSUserAttribute("cost-center")[1]);
		Assert.assertEquals(1, token.getXSUserAttribute("country").length);
		Assert.assertEquals("Germany", token.getXSUserAttribute("country")[0]);
		// client id
		Assert.assertEquals("sb-java-hello-world", token.getClientId());
		// grant type
		Assert.assertEquals("authorization_code", token.getGrantType());

		// logon name
		Assert.assertEquals("Mustermann", token.getLogonName());
		// email
		Assert.assertEquals("max@example.com", token.getEmail());
		// zone
		Assert.assertTrue(token.getSubaccountId().startsWith("11-22-33"));
		// ext attr
		Assert.assertEquals("domain\\group1", token.getAdditionalAuthAttribute("external_group"));
		Assert.assertEquals("abcd1234", token.getAdditionalAuthAttribute("external_id"));

		// service instance id
		Assert.assertEquals("abcd1234", token.getCloneServiceInstanceId());
		// // groups
		// Assert.assertEquals(1, token.getSystemAttribute("xs.saml.groups").length);
		// Assert.assertEquals("g1", token.getSystemAttribute("xs.saml.groups")[0]);
		// role collections
		// Assert.assertEquals(1, token.getSystemAttribute("xs.rolecollections").length);
		// Assert.assertEquals("rc1", token.getSystemAttribute("xs.rolecollections")[0]);
		return "user:" + token.getLogonName();
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
