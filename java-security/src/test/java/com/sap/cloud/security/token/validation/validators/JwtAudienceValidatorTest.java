package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.assertj.core.util.Sets;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtAudienceValidatorTest {

	private Token token;
	private String XSUAA_BROKER_XSAPPNAME = "brokerplanmasterapp!b123";

	@Before
	public void setUp() {
		token = Mockito.mock(Token.class);
		Mockito.when(token.getAudiences()).thenReturn(
				Sets.newLinkedHashSet("client", "foreignclient", "sb-test4!t1.data"));
	}

	@Test
	public void validate_tokenAudienceMatchesClientId() {
		ValidationResult result = new JwtAudienceValidator("client")
				.validate(token);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void validate_tokenAudienceMatchesAppId() {
		Mockito.when(token.getAudiences()).thenReturn(
				Sets.newLinkedHashSet("appId!t1"));
		ValidationResult result = new JwtAudienceValidator("sb-appId!t1")
				.configureTrustedClientId("appId!t1")
				.validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void validate_tokenAudienceMatchesForeignClientId() {
		ValidationResult result = new JwtAudienceValidator("any")
				.configureTrustedClientId("foreignclient")
				.validate(token);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void validate_clientIdMatchesTokenAudienceWithoutDot() {
		// configures token audience
		Mockito.when(token.getAudiences())
				.thenReturn(Sets.newLinkedHashSet("client", "foreignclient", "sb-test4!t1.data.x"));

		// configures audience validator with client-id from VCAP_SERVICES
		ValidationResult result = new JwtAudienceValidator("sb-test4!t1")
				.validate(token);

		assertThat(result.isValid()).isTrue(); // should match
	}

	@Test
	public void validate_brokerClientIdMatchesCloneAudience() {
		// configures token audience
		Mockito.when(token.getAudiences())
				.thenReturn(Sets
						.newLinkedHashSet("sb-f7016e93-8665-4b73-9b46-f99d7808fe3c!b446|" + XSUAA_BROKER_XSAPPNAME));

		// configures audience validator with client-id from VCAP_SERVICES
		ValidationResult result = new JwtAudienceValidator("sb-" + XSUAA_BROKER_XSAPPNAME)
				.configureTrustedClientId(XSUAA_BROKER_XSAPPNAME)
				.validate(token);

		assertThat(result.isValid()).isTrue(); // should match
	}

	@Test
	public void validationFails_brokerClientIdDoesNotMatchCloneAudience() {
		// configures token audience
		Mockito.when(token.getAudiences())
				.thenReturn(Sets.newLinkedHashSet("sb-f7016e93-8665-4b73-9b46-f99d7808fe3c!b446|ANOTHERAPP!b12"));

		// configures audience validator with client-id from VCAP_SERVICES
		ValidationResult result = new JwtAudienceValidator("sb-ANOTHERAPP!b12")
				.configureTrustedClientId("ANOTHERAPP!b12")
				.validate(token);

		assertThat(result.isValid()).isTrue(); // should match
	}

	@Test
	public void validationFails_when_NoTokenAudienceMatches() {
		ValidationResult result = new JwtAudienceValidator("any")
				.configureTrustedClientId("anyother")
				.validate(token);

		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription())
				.isEqualTo(
						"Jwt token with audience [client, foreignclient, sb-test4!t1] is not issued for these clientIds: [any, anyother].");
	}

	@Test
	public void validationShouldFilterEmptyAudiences() {
		Mockito.when(token.getAudiences()).thenReturn(Sets.newLinkedHashSet(".", "test.", " .test2"));

		ValidationResult result = new JwtAudienceValidator("any")
				.validate(token);

		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription())
				.isEqualTo("Jwt token with audience [test] is not issued for these clientIds: [any].");
	}

	@Test
	public void validationFails_when_TokenAudiencesAreEmpty() {
		Mockito.when(token.getAudiences()).thenReturn(Collections.emptySet());

		ValidationResult result = new JwtAudienceValidator("any")
				.validate(token);

		assertThat(result.isErroneous()).isTrue();
		assertThat(result.getErrorDescription())
				.isEqualTo("Jwt token with audience [] is not issued for these clientIds: [any].");
	}

}