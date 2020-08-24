package com.sap.cloud.security.test;

import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;
import sun.security.rsa.RSAPublicKeyImpl;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.test.JwtGenerator.DEFAULT_KEY_ID;
import static com.sap.cloud.security.test.JwtGenerator.SignatureCalculator;
import static com.sap.cloud.security.test.SecurityTestRule.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class JwtGeneratorTest {

	private static RSAKeys keys;
	private JwtGenerator cut;

	private static final Path RESOURCES_PATH = Paths.get(JwtGeneratorTest.class.getResource("/").getPath());

	@ClassRule
	public static TemporaryFolder temporaryFolder = new TemporaryFolder(RESOURCES_PATH.toFile());

	@BeforeClass
	public static void setUpClass() throws Exception {
		keys = RSAKeys.fromKeyFiles("/publicKey.txt", "/privateKey.txt");
	}

	@Before
	public void setUp() {
		cut = JwtGenerator.getInstance(XSUAA, DEFAULT_CLIENT_ID).withPrivateKey(keys.getPrivate());
	}

	@Test
	public void createToken_isNotNull() {
		Token token = cut.createToken();

		assertThat(token).isNotNull();
		assertThat(token.getClaimAsStringList(TokenClaims.AUDIENCE)).contains(DEFAULT_CLIENT_ID);
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo(DEFAULT_CLIENT_ID);
		assertThat(token.getExpiration()).isEqualTo(JwtGenerator.NO_EXPIRE_DATE);
	}

	@Test
	public void createIasToken_isNotNull() {
		cut = JwtGenerator.getInstance(IAS, "T000310")
				.withClaimValue("sub", "P176945")
				.withClaimValue("scope", "john.doe")
				.withClaimValue("iss", "https://application.myauth.com")
				.withClaimValue("first_name", "john")
				.withClaimValue("last_name", "doe")
				.withClaimValue("email", "john.doe@email.org")
				.withClaimValue(TokenClaims.SAP_GLOBAL_USER_ID, "1234567890")
				.withPrivateKey(keys.getPrivate());
		Token token = cut.createToken();

		assertThat(token).isNotNull();
		assertThat(token.getClaimAsString(TokenClaims.AUDIENCE)).isEqualTo("T000310");
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo("T000310");
		assertThat(token.getExpiration()).isEqualTo(JwtGenerator.NO_EXPIRE_DATE);
		assertThat(token.getPrincipal().getName()).isEqualTo("1234567890");
		String encodedModulusN = Base64.getUrlEncoder()
				.encodeToString(((RSAPublicKeyImpl) keys.getPublic()).getModulus().toByteArray());
		assertThat(encodedModulusN).startsWith("AJtUGmczI7RHx3");
	}

	@Test
	public void createToken_withoutPrivateKey_throwsException() {
		assertThatThrownBy(() -> JwtGenerator.getInstance(IAS, "T00001234").createToken())
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void withPrivateKey_usesPrivateKey() throws Exception {
		SignatureCalculator signatureCalculator = Mockito.mock(SignatureCalculator.class);

		when(signatureCalculator.calculateSignature(any(), any(), any())).thenReturn("sig".getBytes());

		JwtGenerator.getInstance(IAS, signatureCalculator, "T00001234").withPrivateKey(keys.getPrivate()).createToken();

		verify(signatureCalculator, times(1)).calculateSignature(eq(keys.getPrivate()), any(), any());
	}

	@Test
	public void withClaim_containsClaim() {
		String email = "john.doe@mail.de";

		Token token = cut
				.withClaimValue(TokenClaims.EMAIL, email)
				.createToken();

		assertThat(token.getClaimAsString(TokenClaims.EMAIL)).isEqualTo(email);
	}

	@Test
	public void withClaimClientId_overwritesClaim() {
		String clientId = "myClientId";

		Token token = cut
				.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, clientId)
				.createToken();

		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo(clientId);
	}

	@Test
	public void withHeaderParameter_containsHeaderParameter() {
		String tokenKeyServiceUrl = "http://localhost/token_keys";
		String keyId = "theKeyId";
		Token token = cut.withHeaderParameter(TokenHeader.JWKS_URL, tokenKeyServiceUrl)
				.withHeaderParameter(TokenHeader.KEY_ID, keyId)
				.createToken();

		assertThat(token.getHeaderParameterAsString(TokenHeader.KEY_ID)).isEqualTo(keyId);
		assertThat(token.getHeaderParameterAsString(TokenHeader.JWKS_URL)).isEqualTo(tokenKeyServiceUrl);
	}

	@Test
	public void withScopes_containsScopeWhenServiceIsXsuaa() {
		String[] scopes = new String[] { "openid", "app1.scope" };
		Token token = cut.withScopes(scopes).createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)).containsExactly(scopes);
	}

	@Test
	public void withLocalScopes_containsGivenScopesAsLocalScopesWhenServiceIsXsuaa() {
		String scopeRead = "Read";
		String scopeWrite = "Write";
		Token token = cut
				.withAppId(DEFAULT_APP_ID)
				.withLocalScopes(scopeRead, scopeWrite).createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES))
				.containsExactlyInAnyOrder(DEFAULT_APP_ID + "." + scopeRead, DEFAULT_APP_ID + "." + scopeWrite);
	}

	@Test
	public void consecutiveScopeCallsOverwriteOldData() {
		String writeScope = "Write";
		String openidScope = "openid";
		Token token = cut
				.withAppId(DEFAULT_APP_ID)
				.withLocalScopes("Read")
				.withLocalScopes(writeScope)
				.withScopes("test")
				.withScopes(openidScope)
				.createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES))
				.containsExactlyInAnyOrder(openidScope, DEFAULT_APP_ID + "." + writeScope);
	}

	@Test
	public void withScopesAndLocalScopes_containsBothScopeTypes() {
		String openidScope = "openid";
		String writeScope = "Write";
		Token token = cut
				.withAppId(DEFAULT_APP_ID)
				.withLocalScopes(writeScope)
				.withScopes(openidScope)
				.createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES))
				.containsExactlyInAnyOrder(openidScope, DEFAULT_APP_ID + "." + writeScope);
	}

	@Test
	public void withLocalScopes_withoutAppId_throwsException() {
		assertThatThrownBy(() -> cut.withLocalScopes("Read").createToken())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("appId has not been set!");
	}

	@Test
	public void withScopes_serviceIsIAS_throwsUnsupportedOperationException() {
		cut = JwtGenerator.getInstance(IAS, "T00001234").withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.withScopes("firstScope").createToken())
				.isInstanceOf(UnsupportedOperationException.class)
				.hasMessage("Scopes are not supported for service IAS");
	}

	@Test
	public void withExpiration_createsTokenWithExpiration() {
		Instant expiration = LocalDate.of(2019, 1, 1).atStartOfDay().toInstant(ZoneOffset.UTC);

		Token token = cut.withExpiration(expiration).createToken();

		assertThat(token.getExpiration()).isEqualTo(expiration);
	}

	@Test
	public void withClaimValuesAudience_isOverridden() {
		Token token = cut.withClaimValues(TokenClaims.AUDIENCE, "app2", "app3").createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.AUDIENCE)).containsExactlyInAnyOrder("app2", "app3");
	}

	@Test
	public void withClaimValue_asJsonObjectContainingString() {
		Token token = cut.withClaimValue("key1", new DefaultJsonObject("{\"key2\" : \"abc\"}"))
				.createToken();

		JsonObject object = token.getClaimAsJsonObject("key1");
		assertThat(object).isNotNull();
		assertThat(object.getAsString("key2")).isEqualTo("abc");
	}

	@Test
	public void withClaimValue_asJsonObjectContainingJsonObject() {
		Token token = cut.withClaimValue("key1", new DefaultJsonObject("{\"key2\" : {\"key3\": \"theValue\"}}"))
				.createToken();

		JsonObject object = token.getClaimAsJsonObject("key1");
		assertThat(object).isNotNull();
		JsonObject innerObject = object.getJsonObject("key2");
		assertThat(innerObject).isNotNull();
		assertThat(innerObject.getAsString("key3")).isEqualTo("theValue");
	}

	@Test
	public void withClaimValue_asJsonObjectContainingList() {
		Token token = cut.withClaimValue("key1", new DefaultJsonObject("{\"key2\": [\"a\", \"b\"]}"))
				.createToken();

		JsonObject object = token.getClaimAsJsonObject("key1");
		assertThat(object).isNotNull();
		List<String> list = object.getAsList("key2", String.class);
		assertThat(list).containsExactly("a", "b");
	}

	@Test
	public void loadClaimsFromFile_doesNotContainValidJson_throwsException() throws IOException {
		File emptyFile = temporaryFolder.newFile("empty");
		String temporaryFolderName = emptyFile.getParentFile().getName();
		String resourcePath = "/" + temporaryFolderName + "/empty";

		assertThatThrownBy(() -> cut.withClaimsFromFile(resourcePath).createToken())
				.isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void loadClaimsFromFile_containsStringClaims() throws IOException {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		assertThat(token.getClaimAsString(TokenClaims.EMAIL)).isEqualTo("test@uaa.org");
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.GRANT_TYPE))
				.isEqualTo("urn:ietf:params:oauth:grant-type:saml2-bearer");
	}

	@Test
	public void loadClaimsFromFile_containsExpirationClaim() throws IOException {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		assertThat(token.getExpiration()).isEqualTo(Instant.ofEpochSecond(1542416800));
	}

	@Test
	public void loadClaimsFromFile_containsJsonObjectClaims() throws IOException {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		JsonObject externalAttributes = token.getClaimAsJsonObject("ext_attr");

		assertThat(externalAttributes).isNotNull();
		assertThat(externalAttributes.getAsString("enhancer")).isEqualTo("XSUAA");
		assertThat(externalAttributes.getAsList("acl", String.class)).containsExactly("app1!t23");
	}

	@Test
	public void loadClaimsFromFile_containsListClaims() throws IOException {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES))
				.containsExactly("openid", "testScope", "testApp.localScope");
		assertThat(token.getClaimAsStringList("empty_list")).isEmpty();
	}

	@Test
	public void fromFile_loadsJsonAndSetsDefaults() throws IOException {
		Token token = cut.fromFile("/token.json").createToken();

		assertThat(token.getHeaderParameterAsString(TokenHeader.KEY_ID)).isEqualTo(DEFAULT_KEY_ID);
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.ZONE_ID)).isEqualTo("zone-id");
		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)).containsExactlyInAnyOrder("openid",
				"app1.scope");
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo(DEFAULT_CLIENT_ID);
	}

	@Test
	public void fromFile_clientTokens_setsSubject() throws IOException {
		Token token = cut.fromFile("/client_token.json").createToken();

		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo(DEFAULT_CLIENT_ID);
		assertThat(token.getClaimAsString(TokenClaims.SUBJECT)).isEqualTo(DEFAULT_CLIENT_ID);
	}

	@Test
	public void fromFile_fileDoesNotExist_throwsException() {
		assertThatThrownBy(() -> cut.fromFile("/doesNotExist.json"))
				.isInstanceOf(IOException.class);
	}

	@Test
	public void fromFile_fileMalformed_throwsException() {
		assertThatThrownBy(() -> cut.fromFile("/publicKey.txt"))
				.isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void createToken_signatureCalculation_NoSuchAlgorithmExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new NoSuchAlgorithmException();
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_signatureCalculation_SignatureExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new SignatureException();
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_signatureCalculation_InvalidKeyExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new InvalidKeyException();
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

}
