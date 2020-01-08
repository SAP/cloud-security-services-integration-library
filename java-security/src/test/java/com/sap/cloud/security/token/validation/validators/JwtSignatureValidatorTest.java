package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.IasToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.xsuaa.client.*;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.*;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class JwtSignatureValidatorTest {
	public static final String APP_ID = "my-app!t1785";
	private Token xsuaaToken;
	private Token iasToken; // contains alg header only, signature that does not match jwks
	private Token xsuaaTokenSignedWithVerificationKey; // signed with verificationkey (from configuration)
	private JwtSignatureValidator cut;
	private OAuth2TokenKeyService tokenKeyServiceMock;
	private OAuth2ServiceEndpointsProvider endpointsProviderMock;
	private OidcConfigurationService oidcConfigurationServiceMock;

	@Before
	public void setup() throws IOException {
		xsuaaToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", UTF_8),
				APP_ID);
		iasToken = new IasToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));

		xsuaaTokenSignedWithVerificationKey = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaAccessTokenRSA256_signedWithVerificationKey.txt", UTF_8), APP_ID);

		endpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProviderMock.getJwksUri()).thenReturn(URI.create("https://myoidcprovider.com/jwks_uri"));

		oidcConfigurationServiceMock = Mockito.mock(OidcConfigurationService.class);
		when(oidcConfigurationServiceMock.retrieveEndpoints(any())).thenReturn(endpointsProviderMock);

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock
				.retrieveTokenKeys(URI.create("https://authentication.stagingaws.hanavlab.ondemand.com/token_keys")))
						.thenReturn(JsonWebKeySetFactory.createFromJson(
								IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8)));

		cut = new JwtSignatureValidator(
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(oidcConfigurationServiceMock));
	}

	@Test
	public void validate_throwsWhenTokenIsNull() {
		assertThatThrownBy(() -> {
			cut.validate(null, "key-id-1", "RS256", null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("token");
	}

	@Test
	public void xsuaa_RSASignatureMatchesJWKS() {
		assertThat(cut.validate(xsuaaToken).isValid(), is(true));
	}

	@Test
	public void iasOidc_RSASignatureMatchesJWKS() throws IOException {
		when(tokenKeyServiceMock.retrieveTokenKeys(URI.create("https://myoidcprovider.com/jwks_uri")))
				.thenReturn(JsonWebKeySetFactory.createFromJson(
						IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8)));
		assertThat(cut.validate(iasToken).isValid(), is(true));
	}

	@Test
	public void generatedToken_SignatureMatchesVerificationkey() {
		OAuth2ServiceConfiguration mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn(
				"-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/2Yr+1z685eiOUlwybRVG9i8wsgOUh+PUGuQL8hgulLZWXU5MbwBLTECAEMQbcRTNVTolkq4i67EP6JesHJIFADbK1Ni0KuMcPuiyOLvDKiDEMnYG1XP3X3WCNfsCVT9YoU+lWIrZr/ZsIvQri8jczr4RkynbTBsPaAOygPUlipqDrpadMO1momNCbea/o6GPn38LxEw609ItfgDGhL6f/yVid5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0frWAPyEfuIW9B+mR/2vGhyU9IbbWpvFXiy9RVbbsM538TCjd5JF2dJvxy24addC4oQIDAQAB-----END PUBLIC KEY-----");
		cut.withOAuth2Configuration(mockConfiguration);
		assertThat(cut.validate(xsuaaTokenSignedWithVerificationKey).isValid(), is(true));
	}

	@Test
	public void validationFails_whenSignatureOfGeneratedTokenDoesNotMatchVerificationkey() {
		OAuth2ServiceConfiguration mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn("INVALID_KEY");
		cut.withOAuth2Configuration(mockConfiguration);

		ValidationResult result = cut.validate(xsuaaTokenSignedWithVerificationKey);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Fallback with configured verificationkey was not successful."));
	}

	@Test
	public void validationFails_whenJwtPayloadModified() {
		String[] tokenHeaderPayloadSignature = xsuaaToken.getAccessToken().split(Pattern.quote("."));
		String[] otherHeaderPayloadSignature = iasToken.getAccessToken().split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(otherHeaderPayloadSignature[1])
				.append(".")
				.append(tokenHeaderPayloadSignature[2]).toString();
		assertThat(cut.validate(new XsuaaToken(tokenWithOthersSignature, APP_ID)).isErroneous(), is(true));
	}

	@Test
	public void validationFails_whenJwtProvidesNoSignature() {
		String[] tokenHeaderPayloadSignature = xsuaaToken.getAccessToken().split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(tokenHeaderPayloadSignature[1]).toString();

		ValidationResult result = cut.validate(tokenWithOthersSignature, "RS256", "key-id-1",
				"https://authentication.stagingaws.hanavlab.ondemand.com/token_keys");
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Jwt token does not consist of 'header'.'payload'.'signature'."));
	}

	@Test
	public void validationFails_whenNoMatchingKey() throws IOException {
		when(tokenKeyServiceMock.retrieveTokenKeys(URI.create("https://myauth.com/jwks_uri")))
				.thenReturn(JsonWebKeySetFactory.createFromJson(
						IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8)));

		ValidationResult result = cut.validate(iasToken.getAccessToken(), "RS256", "default-kid-2",
				"https://myauth.com/jwks_uri");
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString(
						"There is no Json Web Token Key with keyId 'default-kid-2' and type 'RSA' to prove the identity of the Jwt."));
	}

	@Test
	public void validationFails_whenTokenAlgorithmIsNotRSA256() {
		ValidationResult validationResult = cut.validate(xsuaaToken.getAccessToken(), "ES123", "key-id-1",
				"https://myauth.com/jwks_uri");
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Jwt token with signature algorithm 'ES123' can not be verified."));
	}

	@Test
	public void validationFails_whenTokenAlgorithmIsNull() {
		ValidationResult validationResult = cut.validate(xsuaaToken.getAccessToken(), "", "key-id-1",
				"https://myauth.com/jwks_uri");
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Jwt token with signature algorithm '' can not be verified."));
	}

	@Test
	public void validationFails_whenOAuthServerIsUnavailable() throws OAuth2ServiceException {
		when(tokenKeyServiceMock
				.retrieveTokenKeys(any())).thenThrow(OAuth2ServiceException.class);

		ValidationResult result = cut.validate(xsuaaToken.getAccessToken(), "RS256", null,
				"http://unavailable.com/token_keys");
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Error retrieving Json Web Keys from Identity Service"));

		result = cut.validate(iasToken);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Error retrieving Json Web Keys from Identity Service"));
	}

	@Test
	@Ignore
	public void jsonECSignatureMatchesJWKS() {
		String ecSignedToken = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
		assertThat(cut.validate(ecSignedToken, "ES256", "key-id-1", null).isValid(), is(true));
	}

}
