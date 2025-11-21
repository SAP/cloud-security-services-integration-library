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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.x509.X509Certificate;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaTokenExchangeService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.apache.commons.io.IOUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
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
  XsuaaTokenExchangeService xsuaaTokenExchangeService;

	@BeforeEach
	void setup() {
		combiningValidator = Mockito.mock(CombiningValidator.class);
		when(combiningValidator.validate(any())).thenReturn(ValidationResults.createValid());
    xsuaaTokenExchangeService = Mockito.mock(XsuaaTokenExchangeService.class);

    cut = new HybridJwtDecoder(combiningValidator, combiningValidator, false);
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
    cut = new HybridJwtDecoder(combiningValidator, combiningValidator, false);
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
    HybridJwtDecoder cut = new HybridJwtDecoder(xsuaaValidators, null, false);
		String encodedToken = JwtGenerator.getInstance(XSUAA, "theClientId").createToken().getTokenValue();
		assertThrows(JwtException.class, () -> cut.decode(encodedToken));
	}

	@Test
	void instantiateForXsuaaOnly() {
    cut = new HybridJwtDecoder(combiningValidator, null, false);

		// IAS token can't be validated
		String encodedIasToken = jwtGenerator.createToken().getTokenValue();
		assertThrows(BadJwtException.class, () -> cut.decode(encodedIasToken));

		// XSUAA token can be validated
		String encodedXsuaaToken = JwtGenerator.getInstance(XSUAA, "theClientId").createToken().getTokenValue();
		assertEquals("theClientId", cut.decode(encodedXsuaaToken).getClaim(TokenClaims.AUTHORIZATION_PARTY));

	}

  @Test
  void decodeXsuaaToken_withTokenExchangeEnabledAndTokenIsAlreadyXSUAA_doesNotPerformExchange() {
    cut = new HybridJwtDecoder(combiningValidator, combiningValidator, true);

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
    }
  }

  @Test
  void decodeIasToken_withTokenExchangeEnabled_noXSUAAConfigPresent_throwsJwtException() {
    cut = new HybridJwtDecoder(combiningValidator, combiningValidator, true);
    String iasToken = jwtGenerator.createToken().getTokenValue();

    try (MockedStatic<Environments> environments = Mockito.mockStatic(Environments.class)) {
      Environment mockEnvironment = Mockito.mock(Environment.class);
      environments.when(Environments::getCurrent).thenReturn(mockEnvironment);

      when(mockEnvironment.getXsuaaConfiguration()).thenReturn(null);

      JwtException ex =
          assertThrows(
              JwtException.class,
              () -> cut.decode(iasToken),
              "IAS token with failing token exchange must result in JwtException");

      assertTrue(
          ex.getMessage()
              .contains(
                  "Token exchange failed: No XSUAA service configuration found for token exchange."),
          "Exception message should be wrapped with 'Token exchange failed:' prefix");
    }
  }

  @Test
  void decodeIasToken_withTokenExchangeEnabled_errorOnIDTokenRetrieval_throwsJwtException() {
    cut = new HybridJwtDecoder(combiningValidator, combiningValidator, true);
    String iasToken = jwtGenerator.createToken().getTokenValue();
    OAuth2ServiceConfiguration xsuaaConfig = Mockito.mock(OAuth2ServiceConfiguration.class);
    Environment environment = Mockito.mock(Environment.class);
    try (MockedStatic<SecurityContext> securityContext = Mockito.mockStatic(SecurityContext.class);
        MockedStatic<Environments> environments = Mockito.mockStatic(Environments.class)) {
      securityContext.when(SecurityContext::getIdToken).thenReturn(null);
      environments.when(Environments::getCurrent).thenReturn(environment);
      Mockito.when(environment.getXsuaaConfiguration()).thenReturn(xsuaaConfig);

      JwtException ex =
          assertThrows(
              JwtException.class,
              () -> cut.decode(iasToken),
              "IAS token with failing token exchange must result in JwtException");

      assertTrue(
          ex.getMessage()
              .contains(
                  "Token exchange failed: No ID token found in SecurityContext for token exchange."),
          "Exception message should be wrapped with 'Token exchange failed:' prefix");
    }
  }

  @Test
  void decodeIasToken_withTokenExchangeEnabled_performsTokenExchangeAndReturnsExchangedToken()
      throws OAuth2ServiceException {
    cut = new HybridJwtDecoder(combiningValidator, combiningValidator, true);
    String iasAccessTokenValue = jwtGenerator.createToken().getTokenValue();
    Token idToken = Token.create(jwtGenerator.createToken().getTokenValue());
    String exchangedXsuaaTokenValue =
        JwtGenerator.getInstance(XSUAA, "exchangedClientId").createToken().getTokenValue();
    Token exchangedXsuaaToken = Token.create(exchangedXsuaaTokenValue);

    OAuth2ServiceConfiguration xsuaaConfig = Mockito.mock(OAuth2ServiceConfiguration.class);
    Environment environment = Mockito.mock(Environment.class);
    CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
    try (MockedStatic<SecurityContext> securityContext = Mockito.mockStatic(SecurityContext.class);
        MockedStatic<Environments> environments = Mockito.mockStatic(Environments.class);
        MockedStatic<HttpClientFactory> httpClientFactory =
            Mockito.mockStatic(HttpClientFactory.class);
        MockedConstruction<XsuaaTokenExchangeService> exchangeServiceConstruction =
            Mockito.mockConstruction(
                XsuaaTokenExchangeService.class,
                (mock, context) ->
                    Mockito.when(
                            mock.exchangeToXsuaa(
                                eq(idToken), eq(xsuaaConfig), any(OAuth2TokenService.class)))
                        .thenReturn(exchangedXsuaaToken))) {

      securityContext.when(SecurityContext::getIdToken).thenReturn(idToken);
      environments.when(Environments::getCurrent).thenReturn(environment);
      Mockito.when(environment.getXsuaaConfiguration()).thenReturn(xsuaaConfig);
      httpClientFactory.when(() -> HttpClientFactory.create(null)).thenReturn(httpClient);

      Jwt result = cut.decode(iasAccessTokenValue);
      assertEquals(
          "exchangedClientId",
          result.getClaim(TokenClaims.AUTHORIZATION_PARTY),
          "Should use the exchanged XSUAA token, not the original IAS token");
      XsuaaTokenExchangeService constructed = exchangeServiceConstruction.constructed().get(0);
      verify(constructed)
          .exchangeToXsuaa(eq(idToken), eq(xsuaaConfig), any(OAuth2TokenService.class));
      securityContext.verify(() -> SecurityContext.setToken(any()));
    }
  }
}