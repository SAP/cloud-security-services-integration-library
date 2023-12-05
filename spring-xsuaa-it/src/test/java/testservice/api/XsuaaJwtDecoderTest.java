/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package testservice.api;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaResourceServerJwkAutoConfiguration;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import testservice.api.nohttp.MyEventHandler;
import testservice.api.nohttp.SecurityConfiguration;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = { SecurityConfiguration.class, MyEventHandler.class,
		XsuaaAutoConfiguration.class,
		XsuaaResourceServerJwkAutoConfiguration.class })
@ActiveProfiles({ "test.api.nohttp", "uaamock" })
public class XsuaaJwtDecoderTest {

	boolean postActionExecuted;
	JwtDecoder jwtDecoderWithPostAction;

	@Value("${xsuaa.clientid}")
	String clientId;

	@Value("${xsuaa.xsappname}")
	String xsappname;

	@Autowired
	XsuaaServiceConfiguration serviceConfiguration;

	@Autowired
	MyEventHandler eventHandler;

	@Before
	public void setUp() {
		postActionExecuted = false;
		jwtDecoderWithPostAction = new XsuaaJwtDecoderBuilder(serviceConfiguration)
				.withPostValidationActions(token -> postActionExecuted = true).build();
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
}
