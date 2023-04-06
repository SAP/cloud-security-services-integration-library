/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa;

import com.sap.cloud.security.token.Token;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

	/**
	 * Returns the access token to the caller that was fetched by {@link TokenBrokerResolver}
	 * using the Basic auth information from the request header with a
	 * {@link com.sap.cloud.security.token.GrantType#PASSWORD} grant type flow.
	 *
	 * @param token validated and processed access token
	 * @return the access token
	 */
	@GetMapping("/fetchToken")
	public Token returnToken(@AuthenticationPrincipal Token token) {
		/* access to token claims is available via token object, e.g.
				String userName = token.getPrincipal().getName();
				String zoneId = token.getZoneId()
				List<String> scopes = token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
		 */

		return token;
	}

	@GetMapping("/health")
	public String checkHealth(){
		return "OK";
	}
}
