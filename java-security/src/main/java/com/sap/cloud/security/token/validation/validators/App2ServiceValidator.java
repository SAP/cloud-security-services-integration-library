/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.x509.Certificate;
import com.sap.cloud.security.xsuaa.Assertions;
import org.apache.http.impl.client.CloseableHttpClient;

import javax.annotation.Nullable;
import javax.security.auth.x500.X500Principal;

/**
 * Validates if the jwt token is intended for the OAuth2 client of this
 * application, in an App2Service based scenario. The IAS Prooftoken endpoint
 * provides the subject and issuer DN of the X.509 certificate information, this
 * information needs to match the provided certificate.
 */
public class App2ServiceValidator implements Validator<Token> {

	private OAuth2ServiceConfiguration config;
	private ProofTokenDataRetriever proofTokenDataRetriever;
	public App2ServiceValidator(OAuth2ServiceConfiguration config) {
		Assertions.assertNotNull(config, "Service configuration must not be null");
		this.config = config;
		this.proofTokenDataRetriever = new ProofTokenDataRetriever(config);
	}
	public App2ServiceValidator(OAuth2ServiceConfiguration config, CloseableHttpClient httpClient) {
		Assertions.assertNotNull(config, "Service configuration must not be null");
		this.config = config;
		this.proofTokenDataRetriever = new ProofTokenDataRetriever(config, httpClient);
	}
	/**
	 * Validates the cnf thumbprint of X509 certificate against trusted
	 * certificate's thumbprint.
	 * <p>
	 * In case audience contains only a single value, thumbprint comparison is not
	 * performed and request is validated. To guarantee that this single audience is
	 * trusted, use this validator in combination with {@link JwtAudienceValidator}
	 *
	 * @param token
	 *            token to be validated
	 * @return validation result. Result is valid when both thumbprints match in
	 *         case of multiple audiences.
	 */
	@Override
	public ValidationResult validate(Token token) {
		if (token == null) {
			return ValidationResults.createInvalid("No token passed to validate certificate thumbprint");
		}
		// this validator is applied if the token is coming from another application,
		// so azp != client id
		// app2app flows are ignored
		if(!config.getClientId().equals(token.getClaimAsString("azp")) &&
				(token.getClaimAsStringList("ias_apis") == null || token.getClaimAsStringList("ias_apis").size()==0)) {

			Certificate clientCertificate = SecurityContext.getClientCertificate();
			if (clientCertificate == null) {
				return ValidationResults.createInvalid("Client certificate missing from SecurityContext");
			}
			ProofTokenData data = proofTokenDataRetriever.getDataByTokenAndCertificate(token, clientCertificate);
			if(data==null) {
				return ValidationResults.createInvalid(
						"Certificate validation failed with Token 'azp' {} and certificate subject {}",
						token.getClaimAsString("azp"), clientCertificate.getSubjectDN(X500Principal.RFC2253));
			}else{
				return ValidationResults.createValid();
			}
		}else{ // no app2service flow
			return ValidationResults.createValid();
		}
	}

	/**
	 * Extract cnf attribute value of 'x5t#S256' (SHA-256 hashed certificate
	 * thumbprint) from token.
	 *
	 * @param token
	 *            received token
	 * @return cnf value of 'x5t#S256' or null if value is not present
	 */
	@Nullable
	private static String extractCnfThumbprintFromToken(Token token) {
		JsonObject cnf = token.getClaimAsJsonObject(TokenClaims.CNF);
		return cnf == null ? null : cnf.getAsString(TokenClaims.CNF_X5T);
	}

}
