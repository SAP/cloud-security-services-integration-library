/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package testservice.api.v1;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.token.Token;
import com.sap.cloud.security.xsuaa.tokenflows.ClientCredentialsTokenFlow;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@RestController
@Profile({ "test.api.v1" })
public class TestController {

	@Autowired
	XsuaaServiceConfiguration serviceConfiguration;

	@GetMapping("/")
	public String index(@AuthenticationPrincipal Jwt jwt) {
		return String.format("Hello, %s!", jwt.getSubject());
	}

	@GetMapping("/user")
	String message(@AuthenticationPrincipal Token token) {
		// attributes - old style
		assertEquals(2, token.getXSUserAttribute("cost-center").length);
		assertEquals("0815", token.getXSUserAttribute("cost-center")[0]);
		assertEquals("4711", token.getXSUserAttribute("cost-center")[1]);
		assertEquals(1, token.getXSUserAttribute("country").length);
		assertEquals("Germany", token.getXSUserAttribute("country")[0]);
		// client id
		assertEquals("sb-java-hello-world", token.getClientId());
		// grant type
		assertEquals("authorization_code", token.getGrantType());

		// logon name
		assertEquals("Mustermann", token.getLogonName());
		// email
		assertEquals("max@example.com", token.getEmail());
		// zone
		assertTrue(token.getZoneId().endsWith("tenant"));
		// ext attr
		assertEquals("domain\\group1", token.getAdditionalAuthAttribute("external_group"));
		assertEquals("abcd1234", token.getAdditionalAuthAttribute("external_id"));

		// service instance id
		assertEquals("abcd1234", token.getCloneServiceInstanceId());

		return "user:" + token.getLogonName();
	}

	@GetMapping("/scope")
	public void checkScope(@AuthenticationPrincipal Token token) {
		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) token.getAuthorities();
		assertThat(authorities.size(), is(3));
		assertThat(authorities, not(hasItem(new SimpleGrantedAuthority("openid"))));
		assertThat(authorities, hasItem(new SimpleGrantedAuthority("Display")));
		assertThat(authorities, not(hasItem(new SimpleGrantedAuthority("Other"))));
	}

	@GetMapping("/clientCredentialsToken")
	public String requestClientCredentialsToken(@AuthenticationPrincipal Token token) throws TokenFlowException {
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
