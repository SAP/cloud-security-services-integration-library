package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
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
	private Token xsuaaToken;
	private static final URI DUMMY_JKU_URI = URI.create("https://myauth.com/jwks_uri");

	private JwtSignatureValidator cut;
	private OAuth2TokenKeyService tokenKeyServiceMock;
	private OAuth2ServiceConfiguration mockConfiguration;

	@Before
	public void setup() throws IOException {
		xsuaaToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", UTF_8));

		mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.getService()).thenReturn(Service.XSUAA);

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock
				.retrieveTokenKeys(any()))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8));

		cut = new JwtSignatureValidator(
				mockConfiguration,
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(Mockito.mock(OidcConfigurationService.class)));
	}

	@Test
	public void validate_throwsWhenTokenIsNull() {
		assertThatThrownBy(() -> {
			cut.validate(null, "RS256", "keyId", DUMMY_JKU_URI.toString(), null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("token");
	}

	@Test
	public void validate_throwsWhenAlgotithmIsNull() {
		assertThatThrownBy(() -> {
			cut.validate("eyJhbGciOiJSUzI1NiJ9", null, "keyId", DUMMY_JKU_URI.toString(), null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("tokenAlgorithm");
	}

	@Test
	public void validate_throwsWhenKeyIdIsNull() {
		assertThatThrownBy(() -> {
			cut.validate("eyJhbGciOiJSUzI1NiJ9", "RS256", "", DUMMY_JKU_URI.toString(), null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("tokenKeyId");
	}

	@Test
	public void validate_throwsWhenKeysUrlIsNull() {
		assertThatThrownBy(() -> {
			cut.validate("eyJhbGciOiJSUzI1NiJ9", "RS256", "keyId", "", null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("tokenKeysUrl");
	}

	@Test
	public void validationFails_whenJwtPayloadModified() {
		String[] tokenHeaderPayloadSignature = xsuaaToken.getTokenValue().split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder("eyJhbGciOiJSUzI1NiJ9")
				.append(".")
				.append(tokenHeaderPayloadSignature[1])
				.append(".")
				.append(tokenHeaderPayloadSignature[2]).toString();
		assertThat(cut.validate(new XsuaaToken(tokenWithOthersSignature)).isErroneous(), is(true));
	}

	@Test
	public void validationFails_whenJwtProvidesNoSignature() {
		String[] tokenHeaderPayloadSignature = xsuaaToken.getTokenValue().split(Pattern.quote("."));
		String tokenWithNoSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(tokenHeaderPayloadSignature[1]).toString();

		ValidationResult result = cut.validate(tokenWithNoSignature, "RS256", "key-id-1",
				DUMMY_JKU_URI.toString(), null);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Jwt token does not consist of 'header'.'payload'.'signature'."));
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
	}

	@Test
	@Ignore // Not yet supported
	public void jsonECSignatureMatchesJWKS() {
		/*
		 * { "kty": "EC", "kid": "key-id-1", "alg": "ES256", "value":
		 * "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQgb5npLHd0Bk61bNnjK632uwmBfr\nF7I8hoPgaOZjyhh+BrPDO6CL6D/aW/yPObXXm7SpZogmRwGROcOA3yUleg==\n-----END PUBLIC KEY-----"
		 * }
		 */
		String ecSignedToken = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
		assertThat(cut.validate(ecSignedToken, "ES256", "key-id-1", null, null).isValid(), is(true));
	}
}
