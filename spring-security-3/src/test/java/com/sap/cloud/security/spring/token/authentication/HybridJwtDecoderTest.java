/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.x509.X509Constants.FWD_CLIENT_CERT_HEADER;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenExchangeMode;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.x509.X509Certificate;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.apache.commons.io.IOUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class HybridJwtDecoderTest {
	JwtGenerator jwtGenerator = JwtGenerator.getInstance(IAS, "theClientId");
	CombiningValidator<Token> combiningValidator;
	HybridJwtDecoder cut;

	@BeforeEach
	void setup() {
		combiningValidator = Mockito.mock(CombiningValidator.class);
		when(combiningValidator.validate(any())).thenReturn(ValidationResults.createValid());

    cut = new HybridJwtDecoder(combiningValidator, combiningValidator);
	}

	@Test
	void parseJwt() {
		Jwt jwt = HybridJwtDecoder.parseJwt(jwtGenerator.createToken());

		assertEquals(2, jwt.getHeaders().size());
		assertEquals(8, jwt.getClaims().size());
		assertEquals(1, jwt.getExpiresAt().compareTo(Instant.now()));
		assertEquals("theClientId", jwt.getClaim(TokenClaims.AUTHORIZATION_PARTY));
	}

	@Test
	void decodeIasTokenWithoutValidators() {
		String encodedToken = jwtGenerator.createToken().getTokenValue();
		assertEquals("theClientId", cut.decode(encodedToken).getClaim(TokenClaims.AUTHORIZATION_PARTY));
	}

	@Test
	void decodeIasTokenWithProofToken() throws IOException {
		String cert = IOUtils.resourceToString("/certificate.txt", StandardCharsets.UTF_8);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(FWD_CLIENT_CERT_HEADER, cert);
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

		String encodedToken = jwtGenerator.createToken().getTokenValue();
		assertEquals("theClientId", cut.decode(encodedToken).getClaim(TokenClaims.AUTHORIZATION_PARTY));
		assertNotNull(SecurityContext.getClientCertificate());
	}

	@Test
	void decodeIasTokenWithoutFwdCert() {
		ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
		Logger logger = (Logger) LoggerFactory.getLogger(X509Certificate.class);
		listAppender.start();
		logger.addAppender(listAppender);
		MockHttpServletRequest request = new MockHttpServletRequest();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

		String encodedToken = jwtGenerator.createToken().getTokenValue();
		cut.decode(encodedToken);
		Assertions.assertThat(listAppender.list).isEmpty();
		listAppender.stop();
	}

	@Test
	void decodeXsuaaTokenWithoutValidators() {
		String encodedToken = JwtGenerator.getInstance(XSUAA, "theClientId").createToken().getTokenValue();
		assertEquals("theClientId", cut.decode(encodedToken).getClaim(TokenClaims.AUTHORIZATION_PARTY));
	}

	@Test
	void decodeInvalidToken_throwsAccessDeniedException() {
		when(combiningValidator.validate(any())).thenReturn(ValidationResults.createInvalid("error"));
    cut = new HybridJwtDecoder(combiningValidator, combiningValidator);
		String encodedToken = jwtGenerator.createToken().getTokenValue();

		assertThrows(BadJwtException.class, () -> cut.decode(encodedToken));
	}

	@Test
	void decodeWithMissingExpClaim_throwsBadJwtException() {
		String encodedToken = jwtGenerator
				.withClaimValue(TokenClaims.EXPIRATION, "")
				.createToken().getTokenValue();

		assertThrows(BadJwtException.class, () -> cut.decode(encodedToken));
	}

	@Test
	void decodeWithCorruptToken_throwsBadJwtException() {
		assertThrows(BadJwtException.class, () -> cut.decode("Bearer e30="));
		assertThrows(BadJwtException.class, () -> cut.decode("Bearer"));
		assertThrows(BadJwtException.class, () -> cut.decode(null));
		assertThrows(BadJwtException.class, () -> cut.decode("Bearerabc"));
	}

	@Test
	void decode_cantRetrieveJWK() {
		OAuth2ServiceConfiguration configuration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(configuration.getService()).thenReturn(XSUAA);
		when(configuration.getClientId()).thenReturn("theClientId");
		CombiningValidator<Token> xsuaaValidators = JwtValidatorBuilder.getInstance(configuration).build();
    HybridJwtDecoder cut = new HybridJwtDecoder(xsuaaValidators, null);
		String encodedToken = JwtGenerator.getInstance(XSUAA, "theClientId").createToken().getTokenValue();
		assertThrows(JwtException.class, () -> cut.decode(encodedToken));
	}

	@Test
	void instantiateForXsuaaOnly() {
    cut = new HybridJwtDecoder(combiningValidator, null);

		// IAS token can't be validated
		String encodedIasToken = jwtGenerator.createToken().getTokenValue();
		assertThrows(BadJwtException.class, () -> cut.decode(encodedIasToken));

		// XSUAA token can be validated
		String encodedXsuaaToken = JwtGenerator.getInstance(XSUAA, "theClientId").createToken().getTokenValue();
		assertEquals("theClientId", cut.decode(encodedXsuaaToken).getClaim(TokenClaims.AUTHORIZATION_PARTY));

	}

  @Test
  void decodeXsuaaToken_withTokenExchangeEnabledAndTokenIsAlreadyXSUAA_doesNotPerformExchange() {
    cut =
        new HybridJwtDecoder(combiningValidator, combiningValidator, TokenExchangeMode.FORCE_XSUAA);
    String xsuaaToken =
        JwtGenerator.getInstance(XSUAA, "theClientId").createToken().getTokenValue();

    try (MockedStatic<SecurityContext> securityContext =
        Mockito.mockStatic(SecurityContext.class)) {
      Jwt jwt = cut.decode(xsuaaToken);

      assertEquals(
          "theClientId",
          jwt.getClaim(TokenClaims.AUTHORIZATION_PARTY),
          "Decoded XSUAA token should still contain original azp");
      assertEquals(jwt.getTokenValue(), xsuaaToken);
      securityContext.verify(() -> SecurityContext.setToken(any()), Mockito.never());
      securityContext.verify(() -> SecurityContext.setXsuaaToken(any()), times(1));
    }
  }

  @Test
  void decodeIasToken_withTokenExchangeEnabled_errorOnIDTokenRetrieval_throwsJwtException() {
    cut =
        new HybridJwtDecoder(combiningValidator, combiningValidator, TokenExchangeMode.FORCE_XSUAA);
    String iasToken = jwtGenerator.createToken().getTokenValue();
    OAuth2ServiceConfiguration xsuaaConfig = Mockito.mock(OAuth2ServiceConfiguration.class);
    Environment environment = Mockito.mock(Environment.class);
    try (MockedStatic<SecurityContext> securityContext = Mockito.mockStatic(SecurityContext.class);
        MockedStatic<Environments> environments = Mockito.mockStatic(Environments.class)) {
      securityContext.when(SecurityContext::getXsuaaToken).thenReturn(null);
      environments.when(Environments::getCurrent).thenReturn(environment);
      Mockito.when(environment.getXsuaaConfiguration()).thenReturn(xsuaaConfig);

      assertThrows(
          JwtException.class,
          () -> cut.decode(iasToken),
          "IAS token with failing token exchange must result in JwtException");
    }
  }

  @Test
  void decodeIasToken_withTokenExchangeEnabled_performsTokenExchangeAndReturnsExchangedToken() {
    cut =
        new HybridJwtDecoder(combiningValidator, combiningValidator, TokenExchangeMode.FORCE_XSUAA);
    String iasAccessTokenValue = jwtGenerator.createToken().getTokenValue();
    String exchangedXsuaaTokenValue =
        JwtGenerator.getInstance(XSUAA, "exchangedClientId").createToken().getTokenValue();
    Token exchangedXsuaaToken = Token.create(exchangedXsuaaTokenValue);

    OAuth2ServiceConfiguration xsuaaConfig = Mockito.mock(OAuth2ServiceConfiguration.class);
    Environment environment = Mockito.mock(Environment.class);
    try (MockedStatic<SecurityContext> securityContext = Mockito.mockStatic(SecurityContext.class);
        MockedStatic<Environments> environments = Mockito.mockStatic(Environments.class)) {
      securityContext.when(SecurityContext::getXsuaaToken).thenReturn(exchangedXsuaaToken);
      environments.when(Environments::getCurrent).thenReturn(environment);
      Mockito.when(environment.getXsuaaConfiguration()).thenReturn(xsuaaConfig);
      Jwt result = cut.decode(iasAccessTokenValue);
      assertEquals(result.getTokenValue(), exchangedXsuaaTokenValue);
      securityContext.verify(() -> SecurityContext.setToken(any()));
  }
  }

  @Test
  void decodeIasToken_withTokenExchangeEnabled_performsTokenExchangeAndReturnsOriginalToken() {
    cut =
        new HybridJwtDecoder(
            combiningValidator, combiningValidator, TokenExchangeMode.PROVIDE_XSUAA);
    String iasAccessTokenValue = jwtGenerator.createToken().getTokenValue();
    String exchangedXsuaaTokenValue =
        JwtGenerator.getInstance(XSUAA, "exchangedClientId").createToken().getTokenValue();
    Token exchangedXsuaaToken = Token.create(exchangedXsuaaTokenValue);

    OAuth2ServiceConfiguration xsuaaConfig = Mockito.mock(OAuth2ServiceConfiguration.class);
    Environment environment = Mockito.mock(Environment.class);
    try (MockedStatic<SecurityContext> securityContext = Mockito.mockStatic(SecurityContext.class);
        MockedStatic<Environments> environments = Mockito.mockStatic(Environments.class)) {
      securityContext.when(SecurityContext::getXsuaaToken).thenReturn(exchangedXsuaaToken);
      environments.when(Environments::getCurrent).thenReturn(environment);
      Mockito.when(environment.getXsuaaConfiguration()).thenReturn(xsuaaConfig);
      Jwt result = cut.decode(iasAccessTokenValue);
      assertEquals(iasAccessTokenValue, result.getTokenValue());
      securityContext.verify(() -> SecurityContext.setToken(any()));
    }
  }
}
