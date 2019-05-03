package com.sap.cloud.security.xsuaa.token.authentication;

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

import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.Token;
import com.sap.xs2.security.container.SecurityContext;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import testservice.api.nohttp.SecurityConfiguration;

@RunWith(SpringRunner.class)
@SpringBootTest(properties = {
		"xsuaa.xsappname=" + InitializeSecurityContextTest.XSAPPNAME,
		"xsuaa.clientid=" + InitializeSecurityContextTest.CLIENT_ID,
		"xsuaa.url=${mockxsuaaserver.url}" }, classes = { SecurityConfiguration.class})
@ActiveProfiles("test.api.nohttp")
public class InitializeSecurityContextTest {

	static final String XSAPPNAME = "java-hello-world";
	static final String CLIENT_ID = "sb-" + XSAPPNAME;

	@Autowired
	JwtDecoder jwtDecoder;

	@Test
	public void initializeSecurityContext_succeeds() {
		String jwt = new JwtGenerator(CLIENT_ID, "subdomain")
				.addScopes("openid", XSAPPNAME + ".Display", "otherXSAPP.Display")
				.deriveAudiences(true).getToken().getTokenValue();

		assertThat(SecurityContextHolder.getContext().getAuthentication(), is(nullValue()));

		SecurityContext.init(XSAPPNAME, jwtDecoder.decode(jwt), true);

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
		Token token = (Token)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		assertThat(token.getAuthorities(), is(authorities));
		assertThat(token.getClientId(), is(CLIENT_ID));
	}

	@Test
	public void clearSecurityContext_succeeds() {
		String jwt = new JwtGenerator(CLIENT_ID, "subdomain").deriveAudiences(true).getToken().getTokenValue();

		SecurityContext.init(XSAPPNAME, jwtDecoder.decode(jwt), true);
		SecurityContext.clear();

		assertThat(SecurityContextHolder.getContext().getAuthentication(), is(nullValue()));
	}

	@Test(expected = JwtValidationException.class) // An error occurred while attempting to decode the Jwt: Jwt expired at ...
	public void decodeExpiredToken_raisesValidationException() {
		Map customClaims = new HashMap<String, Object>();
		Instant justOutdated = new Date().toInstant().minusSeconds(3600);
		customClaims.put("exp", Date.from(justOutdated)); // token should be expired
		customClaims.put("iat", Date.from(justOutdated.minusSeconds(1000))); // issuedAt must be before expiredAt
		String jwt = new JwtGenerator(CLIENT_ID, "subdomain").addCustomClaims(customClaims).deriveAudiences(true).getToken().getTokenValue();

		jwtDecoder.decode(jwt);
	}
}
