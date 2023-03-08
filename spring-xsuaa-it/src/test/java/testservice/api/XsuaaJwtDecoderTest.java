/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package testservice.api;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.sap.cloud.security.xsuaa.MockXSUAAServerConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaResourceServerJwkAutoConfiguration;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;

import okhttp3.mockwebserver.MockWebServer;
import testservice.api.nohttp.MyEventHandler;
import testservice.api.nohttp.SecurityConfiguration;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = { SecurityConfiguration.class, MyEventHandler.class,
		XsuaaAutoConfiguration.class,
		XsuaaResourceServerJwkAutoConfiguration.class })
@Import(MockXSUAAServerConfiguration.class)
@ActiveProfiles({ "test.api.nohttp", "uaamock" })
public class XsuaaJwtDecoderTest {

	@BeforeAll
	public static void startMockServer(@Autowired MockWebServer xsuaaServer) throws IOException {
		xsuaaServer.start(33195);
	}

	@AfterAll
	public static void shutdownMockServer(@Autowired MockWebServer xsuaaServer) throws IOException {
		xsuaaServer.shutdown();
	}

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
	public void postValidationActionIsExecutedIfSuccess() {
		String jwt = new JwtGenerator(clientId, "subdomain").deriveAudiences(true)
				.setJwtHeaderKeyId("legacy-token-key").getToken().getTokenValue();

		jwtDecoderWithPostAction.decode(jwt);
		assertTrue(postActionExecuted);
	}

	@Test
	public void postValidationActionIsNotExecutedIfFail() {
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
