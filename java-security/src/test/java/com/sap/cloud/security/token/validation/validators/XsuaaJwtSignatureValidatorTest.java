/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

import static com.sap.cloud.security.config.ServiceConstants.XSUAA.UAA_DOMAIN;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

public class XsuaaJwtSignatureValidatorTest {
	private static Token xsuaaToken;
	private static Token xsuaaTokenSignedWithVerificationKey; // signed with verificationkey (from configuration)

	private static XsuaaJwtSignatureValidator cut;
	private static OAuth2ServiceConfiguration mockConfiguration;

	@BeforeAll
	public static void setup() throws IOException {
		/**
		 * Header -------- { "alg": "RS256", "jku":
		 * "https://authentication.stagingaws.hanavlab.ondemand.com/token_keys", "kid":
		 * "key-id-1" } Payload -------- { "iss":
		 * "http://localhost:8080/uaa/oauth/token" }
		 */
		xsuaaToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", UTF_8));
		/**
		 * Header -------- { "jku": "http://localhost:65148/token_keys", "alg": "RS256"
		 * }
		 */
		xsuaaTokenSignedWithVerificationKey = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaAccessTokenRSA256_signedWithVerificationKey.txt", UTF_8));

		mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.getService()).thenReturn(Service.XSUAA);
		when(mockConfiguration.getProperty(UAA_DOMAIN)).thenReturn("authentication.stagingaws.hanavlab.ondemand.com");

		OAuth2TokenKeyService tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock
				.retrieveTokenKeys(URI.create("https://authentication.stagingaws.hanavlab.ondemand.com/token_keys?zid=uaa&client_id=sap_osb"),
						Map.of(HttpHeaders.X_ZID, "uaa")))
								.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8));

		cut = new XsuaaJwtSignatureValidator(
				mockConfiguration,
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(Mockito.mock(OidcConfigurationService.class)));
	}

	@Test
	void xsuaa_RSASignatureMatchesJWKS() {
		assertThat(cut.validate(xsuaaToken).isValid(), is(true));
	}

	@Test
	void generatedToken_SignatureMatchesVerificationkey() {
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn(
				"""
						-----BEGIN PUBLIC KEY-----
						MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/
						2Yr+1z685eiOUlwybRVG9i8wsgOUh+PUGuQL8hgulLZWXU5MbwBLTECAEMQbcRTN
						VTolkq4i67EP6JesHJIFADbK1Ni0KuMcPuiyOLvDKiDEMnYG1XP3X3WCNfsCVT9Y
						oU+lWIrZr/ZsIvQri8jczr4RkynbTBsPaAOygPUlipqDrpadMO1momNCbea/o6GP
						n38LxEw609ItfgDGhL6f/yVid5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0
						frWAPyEfuIW9B+mR/2vGhyU9IbbWpvFXiy9RVbbsM538TCjd5JF2dJvxy24addC4
						oQIDAQAB
						-----END PUBLIC KEY-----""");
		assertThat(cut.validate(xsuaaTokenSignedWithVerificationKey).isValid(), is(true));
	}

	@Test
	void validationFails_whenVerificationkeyIsInvalid() {
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn("INVALIDKEY");

		ValidationResult result = cut.validate(xsuaaTokenSignedWithVerificationKey);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("Fallback validation key"));
	}

	@Test
	void validationFails_whenSignatureOfGeneratedTokenDoesNotMatchVerificationkey() {
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn(
				"-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/2Yr+1z685eiOUlwybRVG9i8wsgOUh+PUGuQL8hgulLZWXU5MbwBLTECAEMQbcRTNVTolkq4i67EP6JesHJIFADbK1Ni0KuMcPuiyOLvDKiDEMnYG1XP3X3WCNfsCVT9YoU+lWIrZr/ZsIvQri8jczr4RkynbTBsPaAOygPUlipqDrpadMO1momNCbea/o6GPn38LxEw609ItfgDGhL6f/yVid5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0frWAPyEfuIW9B+mR/3vGhyU9IbbWpvFXiy9RVbbsM538TCjd5JF2dJvxy24addC4oQIDAQAB-----END PUBLIC KEY-----");

		ValidationResult result = cut.validate(xsuaaTokenSignedWithVerificationKey);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("Signature of Jwt Token is not valid"));
		assertThat(result.getErrorDescription(),
				containsString("(Signature: CetA62rQSNRj93S9mqaHrKJyzONKeEKcEJ9O5wObRD_"));
	}

	@ParameterizedTest
	@CsvSource({
			"cid,	tid, 	?zid=tid&client_id=cid",
			",		tid, 	?zid=tid",
			"' ',	tid, 	?zid=tid",
			"cid,	,		?client_id=cid",
			"cid,	' ',	?client_id=cid",
			",		,		''",
			"' ',	' ',	''"
	})
	void composeQueryParams(String clientId, String appTid, String query) {
		Token tokenMock = Mockito.mock(Token.class);
		Mockito.when(tokenMock.getClientId()).thenReturn(clientId);
		Mockito.when(tokenMock.getAppTid()).thenReturn(appTid);
		assertTrue(cut.composeQueryParameters(tokenMock).endsWith(query));
	}
}
