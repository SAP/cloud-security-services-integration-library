/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;

public class XsuaaJwtSignatureValidatorTest {
	private Token xsuaaToken;
	private Token xsuaaTokenSignedWithVerificationKey; // signed with verificationkey (from configuration)

	private JwtSignatureValidator cut;
	private OAuth2TokenKeyService tokenKeyServiceMock;
	private OAuth2ServiceConfiguration mockConfiguration;

	@Before
	public void setup() throws IOException {
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

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock
				.retrieveTokenKeys(eq(URI.create("https://authentication.stagingaws.hanavlab.ondemand.com/token_keys")),
						isNull(), isNull(), isNull()))
								.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8));

		cut = new XsuaaJwtSignatureValidator(
				mockConfiguration,
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(Mockito.mock(OidcConfigurationService.class)));
	}

	@Test
	public void xsuaa_RSASignatureMatchesJWKS() {
		assertThat(cut.validate(xsuaaToken).isValid(), is(true));
	}

	@Test
	public void validationFails_whenNoJkuHeaderButIssuerIsGiven() throws IOException {
		/**
		 *
		 * Header -------- { "alg": "RS256" } Payload -------- { "iss":
		 * "https://application.myauth.com" }
		 */
		Token tokenWithoutJkuButIssuer = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));
		ValidationResult result = cut.validate(tokenWithoutJkuButIssuer);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("Token does not contain the mandatory " + JsonWebKeyConstants.JKU_PARAMETER_NAME + " header"));
	}

	@Test
	public void generatedToken_SignatureMatchesVerificationkey() {
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn(
				"-----BEGIN PUBLIC KEY-----\n" +
						"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/\n" +
						"2Yr+1z685eiOUlwybRVG9i8wsgOUh+PUGuQL8hgulLZWXU5MbwBLTECAEMQbcRTN\n" +
						"VTolkq4i67EP6JesHJIFADbK1Ni0KuMcPuiyOLvDKiDEMnYG1XP3X3WCNfsCVT9Y\n" +
						"oU+lWIrZr/ZsIvQri8jczr4RkynbTBsPaAOygPUlipqDrpadMO1momNCbea/o6GP\n" +
						"n38LxEw609ItfgDGhL6f/yVid5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0\n" +
						"frWAPyEfuIW9B+mR/2vGhyU9IbbWpvFXiy9RVbbsM538TCjd5JF2dJvxy24addC4\n" +
						"oQIDAQAB\n" +
						"-----END PUBLIC KEY-----");
		assertThat(cut.validate(xsuaaTokenSignedWithVerificationKey).isValid(), is(true));
	}

	@Test
	public void validationFails_whenVerificationkeyIsInvalid() {
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn("INVALIDKEY");

		ValidationResult result = cut.validate(xsuaaTokenSignedWithVerificationKey);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("Fallback validation key"));
	}

	@Test
	public void validationFails_whenSignatureOfGeneratedTokenDoesNotMatchVerificationkey() {
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn(
				"-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/2Yr+1z685eiOUlwybRVG9i8wsgOUh+PUGuQL8hgulLZWXU5MbwBLTECAEMQbcRTNVTolkq4i67EP6JesHJIFADbK1Ni0KuMcPuiyOLvDKiDEMnYG1XP3X3WCNfsCVT9YoU+lWIrZr/ZsIvQri8jczr4RkynbTBsPaAOygPUlipqDrpadMO1momNCbea/o6GPn38LxEw609ItfgDGhL6f/yVid5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0frWAPyEfuIW9B+mR/3vGhyU9IbbWpvFXiy9RVbbsM538TCjd5JF2dJvxy24addC4oQIDAQAB-----END PUBLIC KEY-----");

		ValidationResult result = cut.validate(xsuaaTokenSignedWithVerificationKey);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("Signature of Jwt Token is not valid"));
		assertThat(result.getErrorDescription(), containsString("(Signature: CetA62rQSNRj93S9mqaHrKJyzONKeEKcEJ9O5wObRD_"));
	}

}
