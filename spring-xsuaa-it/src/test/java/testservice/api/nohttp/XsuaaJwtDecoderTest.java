/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package testservice.api.nohttp;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.context.ActiveProfiles;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaResourceServerJwkAutoConfiguration;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;

import testservice.api.MockXsuaaServerConfiguration;

@SpringBootTest(classes = { MyEventHandler.class,
		XsuaaAutoConfiguration.class,
		XsuaaResourceServerJwkAutoConfiguration.class })
@ActiveProfiles({ "test.api.nohttp" })
class XsuaaJwtDecoderTest extends MockXsuaaServerConfiguration {

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

	@BeforeEach
	public void setUp() {
		postActionExecuted = false;
		jwtDecoderWithPostAction = new XsuaaJwtDecoderBuilder(serviceConfiguration)
				.withPostValidationActions(token -> postActionExecuted = true).build();
	}

	@Test
	void postValidationActionIsExecutedIfSuccess() {
		String jwt = new JwtGenerator(clientId, "subdomain").deriveAudiences(true)
				.setJwtHeaderKeyId("legacy-token-key").getToken().getTokenValue();

		jwtDecoderWithPostAction.decode(jwt);
		assertTrue(postActionExecuted);
	}

	@Test
	void postValidationActionIsNotExecutedIfFail() {
		String jwt = new JwtGenerator(clientId, "subdomain").deriveAudiences(true)
				.setJwtHeaderKeyId("legacy-token-key").setJku(null).getToken().getTokenValue();
		try {
			jwtDecoderWithPostAction.decode(jwt);
			fail();
		} catch (JwtException e) {
			assertFalse(postActionExecuted);
		}
	}
}
