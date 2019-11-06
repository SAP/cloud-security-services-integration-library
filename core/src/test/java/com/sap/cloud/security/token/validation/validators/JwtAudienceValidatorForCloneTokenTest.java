package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.validation.MockTokenBuilder;
import com.sap.cloud.security.token.validation.ValidationError;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.is;


public class JwtAudienceValidatorForCloneTokenTest {

	private String XSUAA_BROKER_XSAPPNAME = "brokerplanmasterapp!b123";
	private String XSUAA_BROKER_CLIENT_ID = "sb-" + XSUAA_BROKER_XSAPPNAME;
	private JwtAudienceValidator cut;
	private MockTokenBuilder mockTokenBuilder;

	@Before
	public void setup() {
		cut = new JwtAudienceValidator( "test1!t1", "sb-test1!t1");
		cut.configureAnotherServiceInstance(XSUAA_BROKER_XSAPPNAME, XSUAA_BROKER_CLIENT_ID);

		mockTokenBuilder = new MockTokenBuilder().withExpiration(JwtGenerator.NO_EXPIRE_DATE.toInstant());
	}

	@Test
	public void tokenWithClientId_like_brokerClientId_shouldBeIgnored() {
		mockTokenBuilder.withClientId(XSUAA_BROKER_CLIENT_ID);

		ValidationResult result = cut.validate(mockTokenBuilder.build());

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void cloneTokenClientId_like_brokerClientId_shouldBeAccepted() {
		mockTokenBuilder.withClientId("sb-clone1!b22|" + XSUAA_BROKER_XSAPPNAME);

		ValidationResult result = cut.validate(mockTokenBuilder.build());

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void cloneTokenClientId_unlike_brokerClientId_raisesError() {
		mockTokenBuilder.withClientId("sb-clone1!b22|ANOTHERAPP!b12");

		ValidationResult result = cut.validate(mockTokenBuilder.build());

		assertThat(result.isValid()).isFalse();
		List<ValidationError> errors = result.getErrors();
		Assert.assertThat(errors.get(0).getDescription(),
				is("Jwt token audience matches none of these: [test1!t1, brokerplanmasterapp!b123]"));
	}


}