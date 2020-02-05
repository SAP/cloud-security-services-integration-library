package com.sap.cloud.security.adapter.xs;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.GrantType;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.XsuaaScopeConverter;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.xsa.security.container.XSUserInfoException;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;

import static com.sap.cloud.security.adapter.xs.XSUserInfoAdapter.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

public class XSUserInfoAdapterTest {

	private static final String TEST_APP_ID = "testApp";
	private final XsuaaToken token;
	private XSUserInfoAdapter cut;
	private XsuaaToken emptyToken;

	public XSUserInfoAdapterTest() throws IOException {
		emptyToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaEmptyToken.txt", UTF_8));
		token = new XsuaaToken(IOUtils.resourceToString("/xsuaaUserInfoAdapterToken.txt", UTF_8));
	}

	@Before
	public void setUp() throws XSUserInfoException {
		cut = spy(new XSUserInfoAdapter(token.withScopeConverter(new XsuaaScopeConverter(TEST_APP_ID))));
	}

	// TODO 22.01.20 c5295400: implement external context fallback tests
	@Test
	public void testGetLogonName() throws XSUserInfoException {
		assertThat(cut.getLogonName()).isEqualTo("TestUser");
	}

	@Test
	public void testGetLogonName_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getLogonName()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getLogonName")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testGetGivenName() throws XSUserInfoException {
		assertThat(cut.getGivenName()).isEqualTo("TestUser");
	}

	@Test
	public void testGetGivenName_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getGivenName()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getGivenName")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testGetFamilyName() throws XSUserInfoException {
		assertThat(cut.getFamilyName()).isEqualTo("unknown.org");
	}

	@Test
	public void testGetFamilyName_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getFamilyName()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getFamilyName")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testGetIdentityZone() throws XSUserInfoException {
		assertThat(cut.getIdentityZone()).isEqualTo("paas");
	}

	@Test
	public void testGetSubdomain() throws XSUserInfoException {
		assertThat(cut.getSubdomain()).isEqualTo("paas");
	}

	@Test
	public void testGetClientId() throws XSUserInfoException {
		assertThat(cut.getClientId()).isEqualTo("sb-clone1!b5|LR-master!b5");
	}

	@Test
	public void testGetJsonValue() throws XSUserInfoException {
		assertThat(cut.getJsonValue("cid")).isEqualTo("sb-clone1!b5|LR-master!b5");
	}

	@Test
	public void testGetEmail() throws XSUserInfoException {
		assertThat(cut.getEmail()).isEqualTo("TestUser@uaa.org");
	}

	@Test
	public void testGetEmail_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getEmail()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getEmail")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testGetAppToken() throws IOException {
		assertThat(cut.getAppToken()).isEqualTo(IOUtils.resourceToString("/xsuaaUserInfoAdapterToken.txt", UTF_8));
	}

	@Test
	public void getToken_namespaceNotSystem_throwsException() {
		assertThatThrownBy(() -> cut.getToken("any", "any")).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	public void testGetDBToken() throws XSUserInfoException {
		when(cut.isInForeignMode()).thenReturn(false);
		assertThat(cut.getDBToken()).isEqualTo(cut.getAppToken());
	}

	@Test
	public void testGetHdbToken() throws XSUserInfoException {
		when(cut.isInForeignMode()).thenReturn(false);
		assertThat(cut.getHdbToken()).isEqualTo(cut.getAppToken());
	}

	@Test
	public void getToken_fallbackToTokenValue() throws XSUserInfoException {
		when(cut.isInForeignMode()).thenReturn(false);
		assertThat(cut.getToken(XSUserInfoAdapter.SYSTEM, XSUserInfoAdapter.HDB)).isEqualTo(token.getTokenValue());
	}

	@Test
	public void getToken_fromExternalContext() throws XSUserInfoException {
		String internalToken = "token";
		JsonObject externalContextMock = mock(JsonObject.class);
		when(externalContextMock.getAsString(HDB_NAMEDUSER_SAML)).thenReturn(internalToken);
		XsuaaToken mockToken = createMockToken(externalContextMock);

		cut = new XSUserInfoAdapter(mockToken);

		assertThat(cut.getToken(XSUserInfoAdapter.SYSTEM, XSUserInfoAdapter.HDB)).isEqualTo(internalToken);
	}

	@Test
	public void getToken_fromHDBNamedUserSaml() throws XSUserInfoException {
		String internalToken = "token";
		XsuaaToken mockToken = createMockToken();
		when(mockToken.getClaimAsString(HDB_NAMEDUSER_SAML)).thenReturn(internalToken);
		when(mockToken.getClaimAsJsonObject(XS_USER_ATTRIBUTES)).thenReturn(mock(JsonObject.class));

		cut = spy(new XSUserInfoAdapter(mockToken));
		when(cut.isInForeignMode()).thenReturn(false);

		assertThat(cut.getToken(XSUserInfoAdapter.SYSTEM, XSUserInfoAdapter.HDB)).isEqualTo(internalToken);
	}

	@Test
	public void testGetAttribute() throws XSUserInfoException {
		String[] attribute = cut.getAttribute("usrAttr");
		assertThat(attribute).contains("test");
	}

	@Test
	public void testGetAttribute_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getAttribute("any")).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getAttribute")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testHasAttributes() throws XSUserInfoException {
		assertThat(cut.hasAttributes()).isTrue();
	}

	@Test
	public void testHasAttributes_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.hasAttributes()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("hasAttributes")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testGetSystemAttribute() throws XSUserInfoException {
		String[] systemAttributes = cut.getSystemAttribute("xs.saml.groups");
		assertThat(systemAttributes).contains("g1");
	}

	@Test
	public void testCheckScope() throws XSUserInfoException {
		assertThat(cut.checkScope("testScope")).isTrue();
	}

	@Test
	public void testCheckLocalScope() throws XSUserInfoException {
		assertThat(cut.checkLocalScope("localScope")).isTrue();
	}

	@Test
	public void testCheckLocalScope_appNameNull_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(token.withScopeConverter(null));
		assertThatThrownBy(() -> cut.checkLocalScope("localScope")).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	public void testGetAdditionalAuthAttribute() throws XSUserInfoException {
		assertThat(cut.getAdditionalAuthAttribute("external_id")).isEqualTo("abcd1234");
	}

	@Test
	public void testGetCloneServiceInstanceId() throws XSUserInfoException {
		assertThat(cut.getCloneServiceInstanceId()).isEqualTo("brokerCloneServiceInstanceId");
	}

	@Test
	public void testGetGrantType() throws XSUserInfoException {
		assertThat(cut.getGrantType()).isEqualTo("urn:ietf:params:oauth:grant-type:saml2-bearer");
	}

	@Test
	public void testIsByDefaultInForeignMode() throws XSUserInfoException {
		assertThat(cut.isInForeignMode()).isTrue();
	}

	@Test
	public void testGetSubaccountId() throws XSUserInfoException {
		assertThat(cut.getSubaccountId()).isEqualTo("paas");
	}

	@Test
	public void testGetOrigin() throws XSUserInfoException {
		assertThat(cut.getOrigin()).isEqualTo("useridp");
	}

	@Test
	public void testGetOrigin_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getOrigin()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getOrigin")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void accessAttributes_doNotExist_throwsException() throws IOException, XSUserInfoException {
		String nonExistingAttribute = "doesNotExist";
		cut = new XSUserInfoAdapter(emptyToken.withScopeConverter(new XsuaaScopeConverter(TEST_APP_ID)));

		assertThatThrownBy(() -> cut.getGrantType()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getLogonName()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getFamilyName()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getIdentityZone()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getDBToken()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getCloneServiceInstanceId()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getGrantType()).isInstanceOf(XSUserInfoException.class);

		assertThatThrownBy(() -> cut.getJsonValue(nonExistingAttribute)).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getAttribute(nonExistingAttribute)).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getSystemAttribute(nonExistingAttribute)).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	public void testRequestTokenForClient_isNotImplemented() {
		assertThatThrownBy(() -> cut.requestTokenForClient("", "", ""))
				.isInstanceOf(UnsupportedOperationException.class)
				.hasMessageContaining("Not implemented");
	}

	@Test
	public void testRequestToken_isNotImplemented() {
		assertThatThrownBy(() -> cut.requestToken(null))
				.isInstanceOf(UnsupportedOperationException.class)
				.hasMessageContaining("Not implemented");
	}

	@Test
	public void isByDefaultInForeignMode() throws XSUserInfoException {
		assertThat(cut.isInForeignMode()).isTrue();
	}

	@Test
	@Ignore
	public void isForeignModeFalse_WhenTokenCloneIdMatchesBrokerAppId() throws XSUserInfoException {
		String tokenClientId = "sb-clone1!b22|brokerplanmasterapp!b123"; // cid
		String configurationAppId = "brokerplanmasterapp!b123";

		XsuaaToken token = mock(XsuaaToken.class);
		when(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).thenReturn(tokenClientId);

		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(tokenClientId)
				.withProperty(CFConstants.XSUAA.APP_ID, configurationAppId)
				.build();

		cut = spy(new XSUserInfoAdapter(token, configuration));
		when(cut.getSubdomain()).thenReturn("otherSubDomain");
		assertThat(cut.isInForeignMode()).isFalse();
	}

	@Test
	@Ignore
	public void isForeignModeFalse_WhenClientIdAndPaasSubdomainMatches() throws XSUserInfoException {
		String tokenClientId = "sb-application!t0123"; // cid
		String tokenSubdomain = "brokerplanmasterapp!b123"; // ext_attr -> zdn

		XsuaaToken token = mock(XsuaaToken.class);
		when(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).thenReturn(tokenClientId);

		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(tokenClientId)
				.withProperty("identityzone", tokenSubdomain)
				.build();

		cut = spy(new XSUserInfoAdapter(token, configuration));
		when(cut.getSubdomain()).thenReturn(tokenSubdomain);
		assertThat(cut.isInForeignMode()).isFalse();
	}


	private XsuaaToken createMockToken(GrantType grantType) {
		XsuaaToken mockToken = mock(XsuaaToken.class);
		when(mockToken.getGrantType()).thenReturn(grantType);
		return mockToken;
	}

	private XsuaaToken createMockToken() {
		return createMockToken(GrantType.SAML2_BEARER);
	}

	private XsuaaToken createMockToken(JsonObject externalContext) {
		final XsuaaToken mockToken = createMockToken();
		when(mockToken.hasClaim(EXTERNAL_CONTEXT)).thenReturn(true);
		when(mockToken.getClaimAsJsonObject(EXTERNAL_CONTEXT)).thenReturn(externalContext);
		return mockToken;
	}

}