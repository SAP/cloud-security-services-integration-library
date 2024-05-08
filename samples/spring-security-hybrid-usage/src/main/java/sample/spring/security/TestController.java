/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.security;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.comp.XsuaaTokenComp;
import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.config.Service.XSUAA;

@RestController
public class TestController {

	private static final Logger logger = LoggerFactory.getLogger(TestController.class);

	/**
	 * A (fake) data layer showing global method security features of Spring Security in combination with tokens from
	 * XSUAA.
	 */
	private final DataService dataService;

	@Autowired
	XsuaaServiceConfiguration config;

	@Autowired
	public TestController(DataService dataService) {
		this.dataService = dataService;
	}

	/**
	 * Returns the detailed information of the XSUAA JWT token. Uses a Token retrieved from the security context of
	 * Spring Security.
	 *
	 * @param token
	 * 		the XSUAA token from the request injected by Spring Security.
	 * @return the requested address.
	 */
	@GetMapping("/sayHello")
	public Map<String, String> sayHello(@AuthenticationPrincipal Token token) {

		logger.debug("Got the token: {}", token);

		Map<String, String> result = new HashMap<>();
		result.put("client id", token.getClientId());
		result.put("audiences", token.getClaimAsStringList(TokenClaims.AUDIENCE).toString());
		result.put("zone id", token.getZoneId());
		result.put("family name", token.getClaimAsString(TokenClaims.FAMILY_NAME));
		result.put("given name", token.getClaimAsString(TokenClaims.GIVEN_NAME));
		result.put("email", token.getClaimAsString(TokenClaims.EMAIL));

		if (XSUAA.equals(token.getService())) {
			result.put("(Xsuaa) subaccount id", ((AccessToken) token).getSubaccountId());
			result.put("(Xsuaa) scopes", String.valueOf(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)));
			result.put("grant type", token.getClaimAsString(TokenClaims.XSUAA.GRANT_TYPE));
		}
		return result;
	}

	@GetMapping("/health")
	public String tokenFlows()
			throws GeneralSecurityException, IOException, SocketEndpointAddressException, X509SourceException {

		ClientCertificate clientIdentity = new ClientCertificate(
				X509SourceSingletonWrapper.getInstance().getX509Source().getX509Svid().getChainArray(),
				X509SourceSingletonWrapper.getInstance().getX509Source().getX509Svid().getPrivateKey(),
				config.getClientId());

		logger.info("certificate: {}, key: {}", clientIdentity.getCertificateChain(),
				clientIdentity.getPrivateKey().getAlgorithm());

		OAuth2TokenService oAuth2TokenService = new DefaultOAuth2TokenService(
				HttpClientFactory.create(clientIdentity));
		XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(oAuth2TokenService, new XsuaaDefaultEndpoints(config),
				clientIdentity);
		return tokenFlows.clientCredentialsTokenFlow().execute().getAccessToken();
	}

	@GetMapping("/comp/sayHello")
	public Map<String, String> sayHelloCompatibility(@AuthenticationPrincipal Token token) {
		logger.debug("Got the token: {}", token);
		com.sap.cloud.security.xsuaa.token.Token compToken; // to analyze deprecated methods: XsuaaTokenComp compToken;
		try {
			compToken = XsuaaTokenComp.createInstance(token);
		} catch (IllegalArgumentException e) {
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
		Map<String, String> result = new HashMap<>();
		result.put("grant type", compToken.getGrantType());
		result.put("client id", compToken.getClientId());
		result.put("subaccount id", compToken.getSubaccountId());
		result.put("zone id", compToken.getZoneId());
		result.put("logon name", compToken.getLogonName());
		result.put("family name", compToken.getFamilyName());
		result.put("given name", compToken.getGivenName());
		result.put("email", compToken.getEmail());
		result.put("scopes", String.valueOf(compToken.getScopes()));

		return result;
	}

	/**
	 * An endpoint showing how to use Spring method security. Only if the request principal has the given scope will the
	 * method be called. Otherwise a 403 error will be returned.
	 */
	@GetMapping("/method")
	@PreAuthorize("hasAuthority('Read')")
	public String callMethodRemotely() {
		return dataService.readSensitiveData();
	}

}
