/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.x509.X509Constants.FWD_CLIENT_CERT_HEADER;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenExchangeMode;
import com.sap.cloud.security.token.XsuaaTokenExtension;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.x509.X509Certificate;
import com.sap.cloud.security.xsuaa.client.DefaultXsuaaTokenExtension;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
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
 * A Spring Security {@link JwtDecoder} that decodes and validates JSON Web Tokens (JWTs) issued by
 * either the SAP Identity Authentication Service (IAS) or the SAP Authorization and Trust
 * Management Service (XSUAA).
 *
 * <p>This decoder automatically determines the token's issuer and applies the corresponding
 * validation rules. It also supports hybrid scenarios where an IAS token can be exchanged for an
 * XSUAA token.
 *
 * <p><b>Token Exchange Modes</b></p>
 *
 * The token exchange behavior is controlled by the {@link TokenExchangeMode}, which can be set
 * during instantiation:
 *
 * <ul>
 *   <li>{@link TokenExchangeMode#DISABLED}: No token exchange is performed. The original token is
 *       returned after validation.
 *   <li>{@link TokenExchangeMode#PROVIDE_XSUAA}: XSUAA tokens are validated and returned. IAS tokens are validated and exchanged for XSUAA
 *       tokens. The XSUAA token is stored in {@link SecurityContext}, but the original IAS token is
 *       returned.
 *   <li>{@link TokenExchangeMode#FORCE_XSUAA}: XSUAA tokens are validated and returned. IAS tokens are exchanged for XSUAA tokens, and the
 *       exchanged token is returned. XSUAA tokens are returned directly without exchange.
 * </ul>
 *
 * <p><b>Client Certificate Forwarding</b></p>
 *
 * For mutual TLS (mTLS) scenarios, the decoder automatically extracts an X.509 client certificate
 * from the {@code x-forwarded-client-cert} HTTP header and makes it available via {@link
 * SecurityContext#getClientCertificate()}.
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
  final TokenExchangeMode tokenExchangeMode;

	private final Logger logger = LoggerFactory.getLogger(getClass());

  /**
   * Creates a new instance with validators for XSUAA and IAS tokens. Token exchange is disabled by
   * default.
   *
   * @param xsuaaValidator a {@link CombiningValidator} for validating XSUAA tokens.
   * @param iasValidator a {@link CombiningValidator} for validating IAS tokens (optional).
   */
  public HybridJwtDecoder(
      CombiningValidator<Token> xsuaaValidator, @Nullable CombiningValidator<Token> iasValidator) {
    this(xsuaaValidator, iasValidator, TokenExchangeMode.DISABLED);
  }

  /**
   * Creates a new instance with validators and a specific token exchange mode.
   *
   * @param xsuaaValidator a {@link CombiningValidator} for validating XSUAA tokens.
   * @param iasValidator a {@link CombiningValidator} for validating IAS tokens (optional).
   * @param tokenExchangeMode the {@link TokenExchangeMode} to control token exchange behavior.
   */
  public HybridJwtDecoder(
      CombiningValidator<Token> xsuaaValidator,
      @Nullable CombiningValidator<Token> iasValidator,
      TokenExchangeMode tokenExchangeMode) {
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
        case PROVIDE_XSUAA -> {
          logger.debug("Token exchange mode is PROVIDE_XSUAA. Exchanging token...");
          exchangeToken(token);
        }
        case FORCE_XSUAA -> {
          if (token.getService() == Service.IAS) {
            logger.debug(
                "Token exchange mode is FORCE_XSUAA and token is issued by IAS. Exchanging token...");
            token = exchangeToken(token);
          } else {
            logger.debug(
                "Token exchange mode is FORCE_XSUAA and token is issued by XSUAA. No exchange needed.");
          }
        }
        case DISABLED -> logger.debug("Token exchange is disabled. No exchange performed.");
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
   * Exchanges an IAS token for an XSUAA token using the {@link SecurityContext}.
   *
   * <p>This method facilitates hybrid authentication scenarios. If the provided token is already an
   * XSUAA token, it is returned without modification. Otherwise, the IAS token is stored in the
   * {@link SecurityContext}, and the context is used to trigger the exchange flow.
   *
   * @param token the token to potentially exchange.
   * @return the resulting XSUAA token (either the original or the newly exchanged one).
   * @throws OAuth2ServiceException if the token exchange fails.
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
            checkValidation(validationResult);
		}
		case XSUAA -> {
            validationResult = xsuaaTokenValidators.validate(token);
            checkValidation(validationResult);
            SecurityContext.setXsuaaToken(token);
        }
		default -> throw new BadJwtException("Tokens issued by " + token.getService() + " service aren't supported.");
		}
  }

    private static void checkValidation(ValidationResult validationResult) {
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
