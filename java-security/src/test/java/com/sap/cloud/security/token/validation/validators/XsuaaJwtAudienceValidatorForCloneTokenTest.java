package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.CLIENT_ID;
import static org.assertj.core.api.Assertions.assertThat;

public class XsuaaJwtAudienceValidatorForCloneTokenTest {

	private String XSUAA_BROKER_XSAPPNAME = "brokerplanmasterapp!b123";
	private String XSUAA_BROKER_CLIENT_ID = "sb-" + XSUAA_BROKER_XSAPPNAME;
	private XsuaaJwtAudienceValidator cut;

	private Token token;

	@Before
	public void setup() {
		token = Mockito.mock(Token.class);
		cut = new XsuaaJwtAudienceValidator("test1!t1", "sb-test1!t1");
		cut.configureAnotherServiceInstance(XSUAA_BROKER_XSAPPNAME, XSUAA_BROKER_CLIENT_ID);
	}

	@Test
	public void tokenWithClientId_like_brokerClientId_shouldBeIgnored() {
		Mockito.when(token.getClaimAsString(CLIENT_ID)).thenReturn(XSUAA_BROKER_CLIENT_ID);
		ValidationResult result = cut.validate(token);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void cloneTokenClientId_like_brokerClientId_shouldBeAccepted() {
		Mockito.when(token.getClaimAsString(CLIENT_ID)).thenReturn("sb-clone1!b22|" + XSUAA_BROKER_XSAPPNAME);

		ValidationResult result = cut.validate(token);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void cloneTokenClientId_unlike_brokerClientId_raisesError() {
		Mockito.when(token.getClaimAsString(CLIENT_ID)).thenReturn("sb-clone1!b22|ANOTHERAPP!b12");

		ValidationResult result = cut.validate(token);

		assertThat(result.isValid()).isFalse();
		assertThat(result.getErrorDescription())
				.isEqualTo("Jwt token audience matches none of these: [test1!t1, brokerplanmasterapp!b123].");
	}

	@Test
	public void validate_byBrokerClientId_whenTokenHasNoAudience() {
		Mockito.when(token.getClaimAsString(CLIENT_ID)).thenReturn("sb-clone1!b22|broker!b1");
		Mockito.when(token.getClaimAsStringList(TokenClaims.AUDIENCE)).thenReturn(
				Collections.EMPTY_LIST);
		ValidationResult result = new XsuaaJwtAudienceValidator("broker!b1", "sb-broker!b1").validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void validationFails_byBrokerClientId_whenTokenHasNoAudience() {
		Mockito.when(token.getClaimAsString(CLIENT_ID)).thenReturn("sb-clone1!b22|broker!b1");
		Mockito.when(token.getClaimAsStringList(TokenClaims.AUDIENCE)).thenReturn(
				Collections.EMPTY_LIST);
		ValidationResult result = new XsuaaJwtAudienceValidator("broker!b4", "sb-broker!b4").validate(token);
		assertThat(result.isValid()).isFalse();
		assertThat(result.getErrorDescription()).contains("Jwt token audience matches none of these: [broker!b4].");
	}

}