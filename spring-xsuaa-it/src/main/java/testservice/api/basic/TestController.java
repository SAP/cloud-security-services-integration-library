/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package testservice.api.basic;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.junit.Assert.assertThat;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.token.Token;
import com.sap.cloud.security.xsuaa.tokenflows.ClientCredentialsTokenFlow;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;

@RestController
@Profile({ "test.api.basic" })
public class TestController {

	@Autowired
	XsuaaServiceConfiguration serviceConfiguration;

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
	public String requestToken(@AuthenticationPrincipal Token token) throws TokenFlowException {
		Map<String, String> azMape = new HashMap();
		azMape.put("a", "b");
		azMape.put("c", "d");

		XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(new XsuaaOAuth2TokenService(new RestTemplate()),
				new XsuaaDefaultEndpoints(serviceConfiguration), new ClientCredentials("c1", "s1"));
		ClientCredentialsTokenFlow ccTokenFlow = tokenFlows.clientCredentialsTokenFlow().attributes(azMape)
				.subdomain(token.getSubdomain());

		OAuth2TokenResponse newToken = ccTokenFlow.execute();
		return newToken.getAccessToken();
	}
}
