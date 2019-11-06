package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import com.sap.cloud.security.token.validation.MockTokenTestFactory;
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
	private MockTokenTestFactory mockTokenTestFactory;

	public JwtAudienceValidatorTest() throws IOException {
		tokenWithAudience = createTokenFromTemplate("/audience_1.txt");
		tokenWithoutAudience = createTokenFromTemplate("/audience_2.txt");
		cloneTokenWithAudience = createTokenFromTemplate("/audience_3.txt");

		jwtAudienceValidatorSameClientId = new JwtAudienceValidator("sb-test1!t1", "test1!t1");
		jwtAudienceValidatorOtherGrantedClientId = new JwtAudienceValidator("sb-test2!t1", "test2!t1");
		jwtAudienceValidatorGrantedClientId = new JwtAudienceValidator("sb-test3!t1", "test3!t1");
		jwtAudienceValidatorBrokerPlan = new JwtAudienceValidator("sb-test3!b1", "test3!b1");
	}

	@Before
	public void setUp()  {
		mockTokenTestFactory = new MockTokenTestFactory();
	}

	private Token createTokenFromTemplate(String templateFilename) throws IOException {
		String tokenWithAudienceAsJsonString = IOUtils.resourceToString(templateFilename, StandardCharsets.UTF_8);
		return new TokenImpl(null, tokenWithAudienceAsJsonString, null);
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
		Token token = new MockTokenTestFactory()
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
		ValidationResult result = new JwtAudienceValidator("sb-test4!t1", "test4!t1").validate(tokenWithAudience);

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
		Token tokenWithoutAudienceButScopes = mockTokenTestFactory.withScopes("test2!t1.Display").build();

		ValidationResult result = jwtAudienceValidatorOtherGrantedClientId.validate(tokenWithoutAudienceButScopes);

		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndMatchingScopes() {
		Token tokenWithoutAudienceButScopes = mockTokenTestFactory.withScopes("test3!t1.Display").build();

		ValidationResult result = jwtAudienceValidatorOtherGrantedClientId.validate(tokenWithoutAudienceButScopes);

		assertThat(result.isValid()).isFalse();
		assertThat(result.getErrors()).hasSize(1);
		assertThat(result.getErrors().get(0).getDescription())
				.isEqualTo("Jwt token audience matches none of these: [test2!t1]");
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndScopes() {
		Token tokenWithoutAudienceAndScopes = mockTokenTestFactory.build();

		ValidationResult result = jwtAudienceValidatorOtherGrantedClientId.validate(tokenWithoutAudienceAndScopes);

		assertThat(result.isValid()).isFalse();
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndEmptyScopes() {
		Token tokenWithoutAudienceAndScopes = mockTokenTestFactory.withScopes("[]").build();

		ValidationResult result = jwtAudienceValidatorOtherGrantedClientId.validate(tokenWithoutAudienceAndScopes);

		assertThat(result.isValid()).isFalse();
	}

	@Test
	public void testTokenWithoutClientId() {
		Token tokenWithoutClientId = mockTokenTestFactory.withClientId("").build();

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