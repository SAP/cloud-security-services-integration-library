/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package testservice.api.nohttp;

import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaResourceServerJwkAutoConfiguration;
import com.sap.cloud.security.xsuaa.extractor.LocalAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.SpringSecurityContext;
import com.sap.cloud.security.xsuaa.token.Token;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.test.context.ActiveProfiles;
import testservice.api.MockXsuaaServerConfiguration;
import testservice.api.XsuaaRequestDispatcher;

import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = { MyEventHandler.class,
		XsuaaAutoConfiguration.class,
		XsuaaResourceServerJwkAutoConfiguration.class })
@ActiveProfiles({ "test.api.nohttp" })
class InitializeSpringSecurityContextTest extends MockXsuaaServerConfiguration {
	@Value("${xsuaa.clientid}")
	String clientId;

	@Value("${xsuaa.xsappname}")
	String appId;

	@Autowired
	JwtDecoder jwtDecoder;

	@Autowired
	MyEventHandler eventHandler;

	@Test
	void initializeSecurityContext_succeeds() {
		String jwt = new JwtGenerator(clientId, "subdomain")
				.addScopes("openid", appId + ".Display", "otherXSAPP.Display")
				.deriveAudiences(true).getToken().getTokenValue();

		assertThat(SecurityContextHolder.getContext().getAuthentication(), is(nullValue()));

		SpringSecurityContext.init(jwt, jwtDecoder, new LocalAuthoritiesExtractor(appId));

		// test authentication - isAuthenticated()
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(authentication, is(notNullValue()));
		assertThat(authentication.isAuthenticated(), is(true));

		// test authorities
		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) authentication.getAuthorities();
		assertThat(authorities.size(), is(1));
		assertThat(authorities, hasItem(new SimpleGrantedAuthority("Display")));
		assertThat(authorities, not(hasItem(new SimpleGrantedAuthority("Other"))));

		// test principal (Token)
		Token token = (Token) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		assertThat(token.getAuthorities(), is(authorities));
		assertThat(token.getClientId(), is(clientId));
	}

	@Test
	void clearSecurityContext_succeeds() {
		String jwt = new JwtGenerator(clientId, "subdomain").deriveAudiences(true).getToken().getTokenValue();

		SpringSecurityContext.init(jwt, jwtDecoder, new LocalAuthoritiesExtractor(appId));
		SpringSecurityContext.clear();

		assertNull(SecurityContextHolder.getContext().getAuthentication());
	}

	@Test
	void cacheHit() {
		String jwt = new JwtGenerator(clientId, "subdomain").deriveAudiences(true)
				.setJwtHeaderKeyId("legacy-token-key").getToken().getTokenValue();

		jwtDecoder.decode(jwt);
		int callCountAfterFirstCall = XsuaaRequestDispatcher.getCallCount();

		jwtDecoder.decode(jwt);
		assertEquals(callCountAfterFirstCall, XsuaaRequestDispatcher.getCallCount());
	}

	@Test
		// An error occurred while attempting to decode the Jwt: Jwt expired at ...
	void decodeExpiredToken_raisesValidationException() {
		Map customClaims = new HashMap<String, Object>();
		Instant justOutdated = new Date().toInstant().minusSeconds(3600);
		customClaims.put("exp", Date.from(justOutdated)); // token should be expired
		customClaims.put("iat", Date.from(justOutdated.minusSeconds(1000))); // issuedAt must be before expiredAt
		String jwt = new JwtGenerator(clientId, "subdomain").addCustomClaims(customClaims).deriveAudiences(true)
				.getToken().getTokenValue();

		assertThrows(JwtValidationException.class, () -> jwtDecoder.decode(jwt));
	}

	@Test
	void callEventWithSufficientAuthorization_succeeds() {
		String jwt = new JwtGenerator(clientId, "subdomain")
				.addScopes("openid", appId + ".Display")
				.deriveAudiences(true).getToken().getTokenValue();

		eventHandler = Mockito.spy(eventHandler);
		eventHandler.onEvent(jwt);
		Mockito.verify(eventHandler, Mockito.times(1)).handleEvent();
	}

	@Test
	void callEventWithInsufficientAuthorization_raisesAccessDeniedException() {
		String jwt = new JwtGenerator(clientId, "subdomain")
				.deriveAudiences(true).getToken().getTokenValue();

		assertThrows(AccessDeniedException.class, () -> eventHandler.onEvent(jwt));
	}

	@Test
	void callEventWithInsufficientAuthorization_raisesAccessDeniedException_2() {
		String jwt = new JwtGenerator(clientId, "subdomain")
				.deriveAudiences(true).getToken().getTokenValue();

		assertThrows(AccessDeniedException.class, () -> eventHandler.onEvent(jwt));
	}

	@Test
	void callEventWithNoJwtToken_raisesAccessDeniedException() {
		assertThrows(AccessDeniedException.class, () -> eventHandler.onEvent(null));
	}

	@Test
	void callEventWithNoJwtToken_raisesAccessDeniedException_2() {
		assertThrows(AccessDeniedException.class, () -> eventHandler.onEvent(null));
	}

}
