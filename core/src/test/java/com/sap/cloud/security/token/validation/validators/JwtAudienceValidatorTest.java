package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenTestFactory;
import com.sap.cloud.security.token.validation.MockTokenBuilder;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtAudienceValidatorTest {

	private final Token tokenWithAudience;
	private final Token tokenWithoutAudience;
	private final Token cloneTokenWithAudience;

	private final JwtAudienceValidator jwtAudienceValidatorSameClientId;
	private final JwtAudienceValidator jwtAudienceValidatorOtherGrantedClientId;
	private final JwtAudienceValidator jwtAudienceValidatorGrantedClientId;
	private final JwtAudienceValidator jwtAudienceValidatorBrokerPlan;
	private MockTokenBuilder mockTokenBuilder;

	public JwtAudienceValidatorTest() throws IOException {
		tokenWithAudience = createTokenFromTemplate("/audience_1.txt");
		tokenWithoutAudience = createTokenFromTemplate("/audience_2.txt");
		cloneTokenWithAudience = createTokenFromTemplate("/audience_3.txt");

		jwtAudienceValidatorSameClientId = new JwtAudienceValidator("test1!t1", "sb-test1!t1");
		jwtAudienceValidatorOtherGrantedClientId = new JwtAudienceValidator("test2!t1", "sb-test2!t1");
		jwtAudienceValidatorGrantedClientId = new JwtAudienceValidator("test3!t1", "sb-test3!t1");
		jwtAudienceValidatorBrokerPlan = new JwtAudienceValidator("test3!b1", "sb-test3!b1");
	}

	@Before
	public void setUp() {
		mockTokenBuilder = new MockTokenBuilder();
	}

	private Token createTokenFromTemplate(String templateFilename) throws IOException {
		String tokenWithAudienceAsJsonString = IOUtils.resourceToString(templateFilename, StandardCharsets.UTF_8);
		return TokenTestFactory.createFromJsonPayload(tokenWithAudienceAsJsonString);
	}

	@Test
	public void testSameClientId() {
		ValidationResult result = jwtAudienceValidatorSameClientId.validate(tokenWithAudience);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void testSameClientIdWithoutAudience() {
		ValidationResult result = jwtAudienceValidatorSameClientId.validate(tokenWithoutAudience);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void testExtractAudiencesFromTokenScopes() {
		Token token = new MockTokenBuilder()
				.withScopes("test1!t1.read", "test2!t1.read", "test2!t1.write", ".scopeWithoutAppId").build();

		List<String> audiences = jwtAudienceValidatorSameClientId.getAllowedAudiences(token);

		assertThat(audiences).hasSize(2);
		assertThat(audiences).containsExactly("test1!t1", "test2!t1");
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudience() {
		ValidationResult result = jwtAudienceValidatorOtherGrantedClientId.validate(tokenWithoutAudience);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndDot() {
		ValidationResult result = new JwtAudienceValidator("test4!t1", "sb-test4!t1").validate(tokenWithAudience);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void testOtherGrantedClientId() {
		ValidationResult result = jwtAudienceValidatorGrantedClientId.validate(tokenWithAudience);

		assertThat(result.isValid()).isFalse();
	}

	@Test
	public void testUnGrantedClientId() {
		ValidationResult result = jwtAudienceValidatorGrantedClientId.validate(tokenWithAudience);

		assertThat(result.isValid()).isFalse();
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceButScopes() {
		Token tokenWithoutAudienceButScopes = mockTokenBuilder.withScopes("test2!t1.Display").build();

		ValidationResult result = jwtAudienceValidatorOtherGrantedClientId.validate(tokenWithoutAudienceButScopes);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndMatchingScopes() {
		Token tokenWithoutAudienceButScopes = mockTokenBuilder.withScopes("test3!t1.Display").build();

		ValidationResult result = jwtAudienceValidatorOtherGrantedClientId.validate(tokenWithoutAudienceButScopes);

		assertThat(result.isValid()).isFalse();
		assertThat(result.getErrors()).hasSize(1);
		assertThat(result.getErrors().get(0).getDescription())
				.isEqualTo("Jwt token audience matches none of these: [test2!t1]");
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndScopes() {
		Token tokenWithoutAudienceAndScopes = mockTokenBuilder.build();

		ValidationResult result = jwtAudienceValidatorOtherGrantedClientId.validate(tokenWithoutAudienceAndScopes);

		assertThat(result.isValid()).isFalse();
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndEmptyScopes() {
		Token tokenWithoutAudienceAndScopes = mockTokenBuilder.withScopes("[]").build();

		ValidationResult result = jwtAudienceValidatorOtherGrantedClientId.validate(tokenWithoutAudienceAndScopes);

		assertThat(result.isValid()).isFalse();
	}

	@Test
	public void testTokenWithoutClientId() {
		Token tokenWithoutClientId = mockTokenBuilder.withClientId("").build();

		ValidationResult result = jwtAudienceValidatorSameClientId.validate(tokenWithoutClientId);

		assertThat(result.isValid()).isFalse();
	}

	@Test
	public void testBrokerCloneWithAudience() {
		ValidationResult result = jwtAudienceValidatorBrokerPlan.validate(cloneTokenWithAudience);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void testBrokerCloneWithoutAudience() {
		ValidationResult result = jwtAudienceValidatorBrokerPlan.validate(cloneTokenWithAudience);
		assertThat(result.isValid()).isTrue();
	}

}