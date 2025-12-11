/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.x509.X509Constants.FWD_CLIENT_CERT_HEADER;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaTokenExtension;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.x509.X509Certificate;
import com.sap.cloud.security.xsuaa.client.DefaultXsuaaTokenExtension;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import jakarta.servlet.http.HttpServletRequest;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Decodes and validates JWT tokens issued by XSUAA or Identity Authentication Service (IAS).
 *
 * <p>This decoder supports both XSUAA access tokens and IAS OIDC tokens, automatically selecting
 * the appropriate validation strategy based on the token's issuer. It integrates with the {@link
 * SecurityContext} to enable automatic token exchange in hybrid authentication scenarios.
 *
 * <p><b>Supported Token Types:</b>
 *
 * <ul>
 *   <li><b>XSUAA Access Tokens</b> — Validated using {@code xsuaaValidator}
 *   <li><b>IAS OIDC Tokens</b> — Validated using {@code iasValidator} (optional)
 * </ul>
 *
 * <p><b>Hybrid Authentication (Token Exchange):</b> When {@code enableTokenExchange} is true, IAS
 * tokens are automatically exchanged to XSUAA format after successful validation. This enables
 * Level 0 migration where applications receive IAS tokens but still use XSUAA-based authorization.
 *
 * <p><b>Token Exchange Flow:</b>
 *
 * <ol>
 *   <li>Decode and validate the incoming token (XSUAA or IAS)
 *   <li>If IAS token and exchange enabled, register {@link XsuaaTokenExtension} per-request
 *   <li>Call {@link SecurityContext#getXsuaaToken()} to trigger automatic exchange
 *   <li>Return the exchanged XSUAA token as {@link Jwt}
 * </ol>
 *
 * <p><b>Extension Registration Strategy:</b> This decoder uses <b>per-request extension
 * registration</b> instead of singleton initialization to avoid circular Spring bean dependencies.
 * The {@link DefaultXsuaaTokenExtension} is registered during token exchange, which requires {@link
 * OAuth2TokenService} and {@link OAuth2ServiceConfiguration} that may not be available during bean
 * construction. Since extensions are stateless, re-registration on each request is safe (overwrites
 * are intentional).
 *
 * <p><b>Client Certificate Support:</b> Automatically extracts X.509 client certificates from the
 * {@code x-forwarded-client-cert} header and stores them in {@link SecurityContext} for mTLS
 * scenarios.
 *
 * <p><b>Prerequisites for Token Exchange:</b>
 *
 * <ul>
 *   <li>XSUAA service binding must be present in environment
 *   <li>IAS service binding must have {@code xsuaa-cross-consumption: true} parameter
 *   <li>{@code enableTokenExchange} must be set to {@code true} in constructor
 * </ul>
 *
 * <p><b>Usage Example:</b>
 *
 * <pre>{@code
 * // 1. Create validators for both token types
 * CombiningValidator<Token> xsuaaValidator = JwtValidatorBuilder.getInstance(xsuaaConfig).build();
 * CombiningValidator<Token> iasValidator = JwtValidatorBuilder.getInstance(iasConfig).build();
 *
 * // 2. Create decoder with token exchange enabled
 * HybridJwtDecoder decoder = new HybridJwtDecoder(xsuaaValidator, iasValidator, true);
 *
 * // 3. Use in Spring Security configuration
 * http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(decoder)));
 * }</pre>
 *
 * <p><b>Error Handling:</b>
 *
 * <ul>
 *   <li>{@link BadJwtException} — Token validation fails or unsupported issuer
 *   <li>{@link JwtException} — Token exchange fails (network error, missing XSUAA config)
 * </ul>
 *
 * @see JwtDecoder
 * @see SecurityContext#registerXsuaaTokenExtension(XsuaaTokenExtension)
 * @see DefaultXsuaaTokenExtension
 */
public class HybridJwtDecoder implements JwtDecoder {
	final CombiningValidator<Token> xsuaaTokenValidators;
	final CombiningValidator<Token> iasTokenValidators;
  final String tokenExchangeMode;

	private final Logger logger = LoggerFactory.getLogger(getClass());

  /**
   * Creates instance with a set of validators for validating the access / oidc token issued by the
   * dedicated identity service.
   *
   * @param xsuaaValidator set of validators that should be used to validate a xsuaa access token.
   * @param iasValidator set of validators that should be used to validate an ias oidc token.
   */
  public HybridJwtDecoder(
      CombiningValidator<Token> xsuaaValidator, @Nullable CombiningValidator<Token> iasValidator) {
    this(xsuaaValidator, iasValidator, "disabled");
  }

  /**
   * Creates instance with a set of validators for validating the access / oidc token issued by the
   * dedicated identity service as well as the option to exchange IAS Tokens to XSUAA Token.
   *
   * @param xsuaaValidator set of validators that should be used to validate a xsuaa access token.
   * @param iasValidator set of validators that should be used to validate an ias oidc token.
   * @param tokenExchangeMode string mode to control token exchange behavior. Supported values:
   *     "provideXSUAA", "forceXSUAA", "disabled"
   */
  public HybridJwtDecoder(
      CombiningValidator<Token> xsuaaValidator,
      @Nullable CombiningValidator<Token> iasValidator,
      String tokenExchangeMode) {
    this.xsuaaTokenValidators = xsuaaValidator;
    this.iasTokenValidators = iasValidator;
    this.tokenExchangeMode = tokenExchangeMode;
  }

	@Override
	public Jwt decode(String encodedToken) {
    setClientCertificateFromRequest();
    try {
      Assert.hasText(encodedToken, "encodedToken must neither be null nor empty String.");
      Token token = Token.create(encodedToken);
      validateToken(token);
      logger.debug("Token issued by {} service was successfully validated.", token.getService());
      switch (tokenExchangeMode) {
        case "provideXSUAA" -> {
          logger.debug("Token exchange mode is 'provideXSUAA'. Exchanging token...");
          exchangeToken(token);
        }
        case "forceXSUAA" -> {
          if (token.getService() == Service.IAS) {
            logger.debug(
                "Token exchange mode is 'forceXSUAA' and token is issued by IAS. Exchanging token...");
            token = exchangeToken(token);
          } else {
            logger.debug(
                "Token exchange mode is 'forceXSUAA' and token is issued by XSUAA. No exchange needed.");
          }
        }
        default -> logger.debug("Token exchange is disabled. No exchange performed.");
      }

      return parseJwt(token);
    } catch (OAuth2ServiceException ex) {
      throw new JwtException("Token exchange failed: " + ex.getMessage(), ex);
		} catch (RuntimeException ex) {
			throw new BadJwtException("Error initializing JWT decoder: " + ex.getMessage(), ex);
		}
  }

  private static void setClientCertificateFromRequest() {
    ServletRequestAttributes attrs =
        (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
    if (attrs != null) {
      HttpServletRequest request = attrs.getRequest();
      String clientCert = request.getHeader(FWD_CLIENT_CERT_HEADER);
      if (clientCert != null) {
        SecurityContext.setClientCertificate(X509Certificate.newCertificate(clientCert));
      }
    }
  }

  /**
   * Exchanges an IAS token to XSUAA format for hybrid authentication scenarios.
   *
   * <p>This method registers a {@link XsuaaTokenExtension} per-request to avoid circular Spring
   * bean dependencies. If the extension were created in the constructor, it would require injecting
   * {@link OAuth2TokenService} and {@link OAuth2ServiceConfiguration}, which may cause circular
   * dependency issues in Spring's bean initialization graph.
   *
   * <p><b>Exchange Logic:</b>
   *
   * <ol>
   *   <li>If token is already XSUAA format, return immediately (no exchange needed)
   *   <li>Store IAS token in {@link SecurityContext} for extension access
   *   <li>Retrieve XSUAA configuration from environment
   *   <li>Create {@link OAuth2TokenService} with mTLS client
   *   <li>Register {@link DefaultXsuaaTokenExtension} (overwrites any previous registration)
   *   <li>Call {@link SecurityContext#getXsuaaToken()} to trigger automatic exchange
   * </ol>
   *
   * <p><b>Extension Registration Strategy:</b> Extensions are stateless singletons, so per-request
   * re-registration is safe. The last-registered extension wins, which is intentional since each
   * request operates in its own thread-local context.
   *
   * @param token the token to exchange (IAS token will be exchanged, XSUAA token returned as-is)
   * @return the XSUAA token (either the original token or the exchanged token)
   * @throws OAuth2ServiceException if:
   *     <ul>
   *       <li>No XSUAA service configuration found in environment
   *       <li>Token exchange fails (network error, invalid credentials, etc.)
   *     </ul>
   *
   * @see SecurityContext#registerXsuaaTokenExtension(XsuaaTokenExtension)
   * @see DefaultXsuaaTokenExtension
   */
  private Token exchangeToken(Token token) throws OAuth2ServiceException {
    if (token.getService() == XSUAA) {
      return token;
    }
    SecurityContext.setToken(token);
    return SecurityContext.getXsuaaToken();
  }

  private void validateToken(Token token) {
		ValidationResult validationResult;
		switch (token.getService()) {
		case IAS -> {
			if (iasTokenValidators == null) {
				throw new BadJwtException("Tokens issued by IAS service aren't accepted");
			}
			validationResult = iasTokenValidators.validate(token);
		}
		case XSUAA -> validationResult = xsuaaTokenValidators.validate(token);
		default -> throw new BadJwtException("Tokens issued by " + token.getService() + " service aren't supported.");
		}
		if (validationResult.isErroneous()) {
			if (validationResult.getErrorDescription().contains("JWKS could not be fetched")) {
				throw new JwtException(validationResult.getErrorDescription());
			} else {
				throw new BadJwtException("The token is invalid: " + validationResult.getErrorDescription());
			}
		}
	}

	/**
	 * Parses decoded Jwt token to {@link Jwt}
	 *
	 * @param token
	 * 		the token
	 * @return Jwt class
	 */
	public static Jwt parseJwt(Token token) {
		return new Jwt(token.getTokenValue(), token.getNotBefore(), token.getExpiration(),
				token.getHeaders(), token.getClaims());
	}
}
