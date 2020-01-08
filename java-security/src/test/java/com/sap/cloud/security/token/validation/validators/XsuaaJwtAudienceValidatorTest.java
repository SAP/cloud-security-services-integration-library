package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenTestFactory;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.CLIENT_ID;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.SCOPES;
import static org.assertj.core.api.Assertions.assertThat;

public class XsuaaJwtAudienceValidatorTest {

	private Token token;

	@Before
	public void setUp() {
		token = Mockito.mock(Token.class);
		Mockito.when(token.getClaimAsString(CLIENT_ID)).thenReturn("sb-test1!t1");
	}

	private Token createTokenFromTemplate(String templateFilename) throws IOException {
		String tokenWithAudienceAsJsonString = IOUtils.resourceToString(templateFilename, StandardCharsets.UTF_8);
		return TokenTestFactory.createFromJsonPayload(tokenWithAudienceAsJsonString);
	}

	@Test
	public void extractAudiencesFromTokenScopes() {
		Mockito.when(token.getClaimAsStringList(SCOPES)).thenReturn(
				Arrays.asList("test1!t1.read", "foreign!t1.read", "foreign!t1.write",
						".scopeWithoutAppId, test1!t1.write"));

		List<String> audiences = XsuaaJwtAudienceValidator.getAllowedAudiences(token);

		assertThat(audiences).hasSize(2);
		assertThat(audiences).containsExactly("test1!t1", "foreign!t1");
	}

	@Test
	public void validate_foreignClientId_tokenAudienceMatchesClientId() {
		Mockito.when(token.getClaimAsStringList(TokenClaims.AUDIENCE)).thenReturn(
				Arrays.asList("test1!t1", "foreign!t1", "test4!t1.data"));

		ValidationResult result = new XsuaaJwtAudienceValidator("foreign!t1", "sb-foreign!t1")
				.validate(token);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void validate_foreignClientId_noTokenAudience_canExtractAudienceFromScopes() {
		Mockito.when(token.getClaimAsStringList(TokenClaims.AUDIENCE)).thenReturn(
				Collections.emptyList());
		Mockito.when(token.getClaimAsStringList(SCOPES)).thenReturn(
				Arrays.asList("foreign!t1.write", "test1!t1.read"));

		ValidationResult result = new XsuaaJwtAudienceValidator("foreign!t1", "sb-foreign!t1")
				.validate(token);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void validationFails_noTokenClientId() {
		Mockito.when(token.getClaimAsString(CLIENT_ID)).thenReturn("");
		ValidationResult result = new XsuaaJwtAudienceValidator("test1!t1", "sb-test1!t1")
				.validate(token);

		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription()).startsWith("Jwt token must contain 'cid'");
	}

	@Test
	public void validationFails_foreignClientId_whenNoAudienceMatches() {
		Mockito.when(token.getClaimAsStringList(TokenClaims.AUDIENCE)).thenReturn(
				Arrays.asList("test1!t1", "foreign!t1", "test4!t1.data", "test3!t2"));

		ValidationResult result = new XsuaaJwtAudienceValidator("test3!t1", "sb-test3!t1").validate(token);

		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription())
				.isEqualTo("Jwt token audience matches none of these: [test3!t1].");
	}

	@Test
	public void validationFails_foreignClientId_whenTokenHasNoAudienceAndScopes() {
		Mockito.when(token.getClaimAsStringList(TokenClaims.AUDIENCE)).thenReturn(
				Collections.emptyList());
		Mockito.when(token.getClaimAsStringList(SCOPES)).thenReturn(
				Collections.emptyList());

		ValidationResult result = new XsuaaJwtAudienceValidator("foreign!t1", "sb-foreign!t1").validate(token);

		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription())
				.isEqualTo("Jwt token audience matches none of these: [foreign!t1].");
	}

	@Test
	public void validate_byTokenClientId_whenTokenHasNoAudienceAndScopes() {
		Mockito.when(token.getClaimAsStringList(TokenClaims.AUDIENCE)).thenReturn(
				Collections.emptyList());
		Mockito.when(token.getClaimAsStringList(SCOPES)).thenReturn(
				Collections.emptyList());

		ValidationResult result = new XsuaaJwtAudienceValidator("test1!t1", "sb-test1!t1").validate(token);

		assertThat(result.isValid()).isTrue();
	}

}