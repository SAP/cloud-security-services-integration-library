package testservice.api;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaResourceServerJwkAutoConfiguration;
import com.sap.cloud.security.xsuaa.mock.XsuaaRequestDispatcher;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.Token;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import com.sap.xs2.security.container.SecurityContext;

import testservice.api.nohttp.MyEventHandler;
import testservice.api.nohttp.SecurityConfiguration;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = { SecurityConfiguration.class, MyEventHandler.class,
		XsuaaAutoConfiguration.class,
		XsuaaResourceServerJwkAutoConfiguration.class })
@ActiveProfiles({ "test.api.nohttp", "uaamock" })
public class InitializeSecurityContextTest {
	@Value("${xsuaa.clientid}")
	String clientId;

	@Value("${xsuaa.xsappname}")
	String xsappname;

	@Autowired
	JwtDecoder jwtDecoder;

	@Autowired
	XsuaaServiceConfiguration serviceConfiguration;

	boolean postActionExecuted;
	JwtDecoder jwtDecoderWithPostAction;

	@Autowired
	MyEventHandler eventHandler;

	@Before
	public void setUp() {
		postActionExecuted = false;
		jwtDecoderWithPostAction = new XsuaaJwtDecoderBuilder(serviceConfiguration)
				.withPostValidationAction(token -> postActionExecuted = true).build();
	}

	@Test
	public void initializeSecurityContext_succeeds() {
		String jwt = new JwtGenerator(clientId, "subdomain")
				.addScopes("openid", xsappname + ".Display", "otherXSAPP.Display")
				.deriveAudiences(true).getToken().getTokenValue();

		assertThat(SecurityContextHolder.getContext().getAuthentication(), is(nullValue()));

		SecurityContext.init(xsappname, jwtDecoder.decode(jwt), true);

		// test authentication - isAuthenticated()
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(authentication, is(notNullValue()));
		assertThat(authentication.isAuthenticated(), is(true));

		// test authorities
		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) authentication.getAuthorities();
		Assert.assertThat(authorities.size(), is(1));
		Assert.assertThat(authorities, hasItem(new SimpleGrantedAuthority("Display")));
		Assert.assertThat(authorities, not(hasItem(new SimpleGrantedAuthority("Other"))));

		// test principal (Token)
		Token token = (Token) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		assertThat(token.getAuthorities(), is(authorities));
		assertThat(token.getClientId(), is(clientId));
	}

	@Test
	public void clearSecurityContext_succeeds() {
		String jwt = new JwtGenerator(clientId, "subdomain").deriveAudiences(true).getToken().getTokenValue();

		SecurityContext.init(xsappname, jwtDecoder.decode(jwt), true);
		SecurityContext.clear();

		assertThat(SecurityContextHolder.getContext().getAuthentication(), is(nullValue()));
	}

	@Test
	public void cacheHit() {
		String jwt = new JwtGenerator(clientId, "subdomain").deriveAudiences(true)
				.setJwtHeaderKeyId("legacy-token-key").getToken().getTokenValue();

		jwtDecoder.decode(jwt);
		int callCountAfterFirstCall = XsuaaRequestDispatcher.getCallCount();

		jwtDecoder.decode(jwt);
		Assert.assertEquals(callCountAfterFirstCall, XsuaaRequestDispatcher.getCallCount());
	}

	@Test
	public void postValidationActionIsExecutedIfSuccess() {
		String jwt = new JwtGenerator(clientId, "subdomain").deriveAudiences(true)
				.setJwtHeaderKeyId("legacy-token-key").getToken().getTokenValue();

		jwtDecoderWithPostAction.decode(jwt);
		Assert.assertTrue(postActionExecuted);
	}

	@Test
	public void postValidationActionIsNotExecutedIfFail() {
		String jwt = new JwtGenerator(clientId, "subdomain").deriveAudiences(true)
				.setJwtHeaderKeyId("legacy-token-key").setJku(null).getToken().getTokenValue();
		try {
			jwtDecoderWithPostAction.decode(jwt);
			Assert.fail();
		} catch (JwtException e) {
			Assert.assertFalse(postActionExecuted);
		}
	}

	@Test(expected = JwtException.class)
	public void missingJkuFails() {
		String jwt = new JwtGenerator(clientId, "subdomain").deriveAudiences(true)
				.setJwtHeaderKeyId("legacy-token-key").setJku(null).getToken().getTokenValue();

		jwtDecoder.decode(jwt);
	}

	@Test(expected = JwtValidationException.class)
	// An error occurred while attempting to decode the Jwt: Jwt expired at ...
	public void decodeExpiredToken_raisesValidationException() {
		Map customClaims = new HashMap<String, Object>();
		Instant justOutdated = new Date().toInstant().minusSeconds(3600);
		customClaims.put("exp", Date.from(justOutdated)); // token should be expired
		customClaims.put("iat", Date.from(justOutdated.minusSeconds(1000))); // issuedAt must be before expiredAt
		String jwt = new JwtGenerator(clientId, "subdomain").addCustomClaims(customClaims).deriveAudiences(true)
				.getToken().getTokenValue();

		jwtDecoder.decode(jwt);
	}

	@Test
	public void callEventWithSufficientAuthorization_succeeds() {
		String jwt = new JwtGenerator(clientId, "subdomain")
				.addScopes("openid", xsappname + ".Display")
				.deriveAudiences(true).getToken().getTokenValue();

		eventHandler.onEvent(jwt);
	}

	@Test(expected = AccessDeniedException.class)
	public void callEventWithInsufficientAuthorization_raisesAccessDeniedException() {
		String jwt = new JwtGenerator(clientId, "subdomain")
				.deriveAudiences(true).getToken().getTokenValue();

		eventHandler.onEvent(jwt);
	}

	@Test(expected = AccessDeniedException.class)
	public void callEventWithNoJwtToken_raisesAccessDeniedException() {
		eventHandler.onEvent(null);
	}

}
