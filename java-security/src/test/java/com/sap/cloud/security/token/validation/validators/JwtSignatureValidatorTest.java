package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.xsuaa.client.*;
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
		xsuaaToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", UTF_8));
		iasToken = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));

		xsuaaTokenSignedWithVerificationKey = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaAccessTokenRSA256_signedWithVerificationKey.txt", UTF_8));

		endpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProviderMock.getJwksUri()).thenReturn(URI.create("https://myoidcprovider.com/jwks_uri"));

		oidcConfigurationServiceMock = Mockito.mock(OidcConfigurationService.class);
		when(oidcConfigurationServiceMock.retrieveEndpoints(any())).thenReturn(endpointsProviderMock);

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock
				.retrieveTokenKeys(URI.create("https://authentication.stagingaws.hanavlab.ondemand.com/token_keys")))
						.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8));

		cut = new JwtSignatureValidator(
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(oidcConfigurationServiceMock));
	}

	@Test
	public void validate_throwsWhenTokenIsNull() {
		assertThatThrownBy(() -> {
			cut.validate(null, "key-id-1", "RS256", null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("token");
	}

	@Test
	public void xsuaa_RSASignatureMatchesJWKS() {
		assertThat(cut.validate(xsuaaToken).isValid(), is(true));
	}

	@Test
	public void iasOidc_RSASignatureMatchesJWKS() throws IOException {
		when(tokenKeyServiceMock.retrieveTokenKeys(URI.create("https://myoidcprovider.com/jwks_uri")))
				.thenReturn(IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));
		assertThat(cut.validate(iasToken).isValid(), is(true));
	}

	@Test
	public void generatedToken_SignatureMatchesVerificationkey() {
		OAuth2ServiceConfiguration mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
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
		cut.withOAuth2Configuration(mockConfiguration);
		assertThat(cut.validate(xsuaaTokenSignedWithVerificationKey).isValid(), is(true));
	}

	@Test
	public void validationFails_whenVerificationkeyIsInvalid() {
		OAuth2ServiceConfiguration mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn("INVALIDKEY");
		cut.withOAuth2Configuration(mockConfiguration);

		ValidationResult result = cut.validate(xsuaaTokenSignedWithVerificationKey);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Fallback with configured verificationkey was not successful."));
	}

	@Test
	public void validationFails_whenSignatureOfGeneratedTokenDoesNotMatchVerificationkey() {
		OAuth2ServiceConfiguration mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn(
				"-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/2Yr+1z685eiOUlwybRVG9i8wsgOUh+PUGuQL8hgulLZWXU5MbwBLTECAEMQbcRTNVTolkq4i67EP6JesHJIFADbK1Ni0KuMcPuiyOLvDKiDEMnYG1XP3X3WCNfsCVT9YoU+lWIrZr/ZsIvQri8jczr4RkynbTBsPaAOygPUlipqDrpadMO1momNCbea/o6GPn38LxEw609ItfgDGhL6f/yVid5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0frWAPyEfuIW9B+mR/3vGhyU9IbbWpvFXiy9RVbbsM538TCjd5JF2dJvxy24addC4oQIDAQAB-----END PUBLIC KEY-----");
		cut.withOAuth2Configuration(mockConfiguration);

		ValidationResult result = cut.validate(xsuaaTokenSignedWithVerificationKey);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Signature of Jwt Token is not valid"));
	}

	@Test
	public void validationFails_whenJwtPayloadModified() {
		String[] tokenHeaderPayloadSignature = xsuaaToken.getTokenValue().split(Pattern.quote("."));
		String[] otherHeaderPayloadSignature = iasToken.getTokenValue().split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(otherHeaderPayloadSignature[1])
				.append(".")
				.append(tokenHeaderPayloadSignature[2]).toString();
		assertThat(cut.validate(new XsuaaToken(tokenWithOthersSignature)).isErroneous(), is(true));
	}

	@Test
	public void validationFails_whenJwtProvidesNoSignature() {
		String[] tokenHeaderPayloadSignature = xsuaaToken.getTokenValue().split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(tokenHeaderPayloadSignature[1]).toString();

		ValidationResult result = cut.validate(tokenWithOthersSignature, "RS256", "key-id-1",
				"https://authentication.stagingaws.hanavlab.ondemand.com/token_keys", null);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Jwt token does not consist of 'header'.'payload'.'signature'."));
	}

	@Test
	public void validationFails_whenNoMatchingKey() throws IOException {
		when(tokenKeyServiceMock.retrieveTokenKeys(URI.create("https://myauth.com/jwks_uri")))
				.thenReturn(IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));

		ValidationResult result = cut.validate(iasToken.getTokenValue(), "RS256", "default-kid-2",
				"https://myauth.com/jwks_uri", null);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString(
						"There is no Json Web Token Key with keyId 'default-kid-2' and type 'RSA' to prove the identity of the Jwt."));
	}

	@Test
	public void validationFails_whenTokenAlgorithmIsNotRSA256() {
		ValidationResult validationResult = cut.validate(xsuaaToken.getTokenValue(), "ES123", "key-id-1",
				"https://myauth.com/jwks_uri", null);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Jwt token with signature algorithm 'ES123' is not supported."));
	}

	@Test
	public void validationFails_whenTokenAlgorithmIsNone() {
		ValidationResult validationResult = cut.validate(xsuaaToken.getTokenValue(), "NONE", "key-id-1",
				"https://myauth.com/jwks_uri", null);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Jwt token with signature algorithm 'NONE' is not supported."));
	}

	@Test
	public void validationFails_whenOAuthServerIsUnavailable() throws OAuth2ServiceException {
		when(tokenKeyServiceMock
				.retrieveTokenKeys(any())).thenThrow(OAuth2ServiceException.class);

		ValidationResult result = cut.validate(xsuaaToken.getTokenValue(), "RS256", "key-id-1",
				"http://unavailable.com/token_keys", null);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Error retrieving Json Web Keys from Identity Service"));

		result = cut.validate(iasToken);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Error retrieving Json Web Keys from Identity Service"));
	}

	@Test
	@Ignore // Not yet supported
	public void jsonECSignatureMatchesJWKS() {
		/*{
			"kty": "EC",
				"kid": "key-id-1",
				"alg": "ES256",
				"value": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQgb5npLHd0Bk61bNnjK632uwmBfr\nF7I8hoPgaOZjyhh+BrPDO6CL6D/aW/yPObXXm7SpZogmRwGROcOA3yUleg==\n-----END PUBLIC KEY-----"
		}*/
		String ecSignedToken = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
		assertThat(cut.validate(ecSignedToken, "ES256", "key-id-1", null, null).isValid(), is(true));
	}

}
