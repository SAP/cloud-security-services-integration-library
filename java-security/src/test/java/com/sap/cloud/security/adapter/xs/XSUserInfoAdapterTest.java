/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.adapter.xs;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.ServiceConstants;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.tokenflows.ClientCredentialsTokenFlow;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.UserTokenFlow;
import com.sap.xsa.security.container.XSUserInfoException;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.stubbing.OngoingStubbing;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.sap.cloud.security.adapter.xs.XSUserInfoAdapter.*;
import static com.sap.cloud.security.config.cf.ServiceConstants.XSUAA.IDENTITY_ZONE;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class XSUserInfoAdapterTest {

	private static final String TEST_APP_ID = "testApp";
	private XsuaaToken token;
	private XSUserInfoAdapter cut;
	private XsuaaToken emptyToken;

	XSUserInfoAdapterTest() throws IOException {
		emptyToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaEmptyToken.txt", UTF_8));
		token = new XsuaaToken(IOUtils.resourceToString("/xsuaaUserInfoAdapterToken.txt", UTF_8));
	}

	@BeforeEach
	void setUp() throws XSUserInfoException {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId("sb-clone1!b5|LR-master!b5")
				.withProperty(ServiceConstants.XSUAA.APP_ID, "brokerplanmasterapp!b123")
				.withProperty(IDENTITY_ZONE, "paas")
				.build();
		cut = new XSUserInfoAdapter(token.withScopeConverter(new XsuaaScopeConverter(TEST_APP_ID)), configuration);
	}

	@Test
	void constructors() throws XSUserInfoException {
		assertThat(new XSUserInfoAdapter((Object) token).getLogonName()).isEqualTo("TestUser");
		assertThat(new XSUserInfoAdapter((Token) token).getLogonName()).isEqualTo("TestUser");
		assertThat(new XSUserInfoAdapter((AccessToken) token).getLogonName()).isEqualTo("TestUser");
		assertThatThrownBy(() -> new XSUserInfoAdapter(null)).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("null")
				.hasMessageContaining("instance of AccessToken");
		assertThatThrownBy(() -> new XSUserInfoAdapter("Tester")).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("String")
				.hasMessageContaining("instance of AccessToken");
	}

	@Test
	void testGetLogonName() throws XSUserInfoException {
		assertThat(cut.getLogonName()).isEqualTo("TestUser");
	}

	@Test
	void testGetLogonName_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getLogonName()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getLogonName")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	void testGetGivenName() throws XSUserInfoException {
		assertThat(cut.getGivenName()).isEqualTo("TestUser");
	}

	@Test
	void testGetGivenName_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getGivenName()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getGivenName")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	void testGetFamilyName() throws XSUserInfoException {
		assertThat(cut.getFamilyName()).isEqualTo("unknown.org");
	}

	@Test
	void testGetFamilyName_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getFamilyName()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getFamilyName")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	void testGetIdentityZone() throws XSUserInfoException {
		assertThat(cut.getZoneId()).isEqualTo("paas");
	}

	@Test
	void testGetSubdomain() throws XSUserInfoException {
		assertThat(cut.getSubdomain()).isEqualTo("paas");
	}

	@Test
	void testGetClientId() throws XSUserInfoException {
		assertThat(cut.getClientId()).isEqualTo("sb-clone1!b5|LR-master!b5");
	}

	@Test
	void testGetEmail() throws XSUserInfoException {
		assertThat(cut.getEmail()).isEqualTo("TestUser@uaa.org");
	}

	@Test
	void testGetEmail_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getEmail()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getEmail")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	void testGetAppToken() throws IOException {
		assertThat(cut.getAppToken()).isEqualTo(IOUtils.resourceToString("/xsuaaUserInfoAdapterToken.txt", UTF_8));
	}

	@Test
	void getToken_namespaceNotSystem_throwsException() {
		assertThatThrownBy(() -> cut.getToken("any", "any")).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	void testGetDBToken() throws XSUserInfoException {
		assertThat(cut.getHdbToken()).isEqualTo(cut.getAppToken());
	}

	@Test
	void testGetDBToken_onEmptyToken_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(emptyToken);

		assertThatThrownBy(() -> cut.getHdbToken()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getHdbToken()).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	void testGetHdbToken() throws XSUserInfoException {
		assertThat(cut.getHdbToken()).isEqualTo(cut.getAppToken());
	}

	@Test
	void getToken_fallbackToTokenValue() throws XSUserInfoException {
		assertThat(cut.getToken(XSUserInfoAdapter.SYSTEM, XSUserInfoAdapter.HDB)).isEqualTo(token.getTokenValue());
	}

	@Test
	void getToken_fromExternalContext() throws XSUserInfoException {
		XsuaaToken mockToken = createMockToken("token");

		cut = new XSUserInfoAdapter(mockToken);

		assertThat(cut.getToken(XSUserInfoAdapter.SYSTEM, XSUserInfoAdapter.HDB)).isEqualTo("token");
	}

	@Test
	void getToken_fromHDBNamedUserSaml() throws XSUserInfoException {
		String internalToken = "token";
		XsuaaToken mockToken = createMockToken();
		when(mockToken.getClaimAsString(HDB_NAMEDUSER_SAML)).thenReturn(internalToken);
		when(mockToken.getClaimAsJsonObject(XS_USER_ATTRIBUTES)).thenReturn(mock(JsonObject.class));

		cut = spy(new XSUserInfoAdapter(mockToken));
		doReturn(false).when(cut).isInForeignMode();

		assertThat(cut.getToken(XSUserInfoAdapter.SYSTEM, XSUserInfoAdapter.HDB)).isEqualTo(internalToken);
	}

	@Test
	void testGetAttribute() throws XSUserInfoException {
		String[] attribute = cut.getAttribute("usrAttr");
		assertThat(attribute).contains("test");
	}

	@Test
	void testGetAttribute_emptyArray() {
		String[] attribute = cut.getAttribute("emptyArray");
		assertThat(attribute).isEmpty();
	}

	@Test
	void testGetAttribute_nonExisting() {
		assertThatThrownBy(() -> cut.getAttribute("nonExisting")).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	void testGetAttribute_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getAttribute("any")).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getAttribute")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	void testHasAttributes_true() throws XSUserInfoException {
		assertThat(cut.hasAttributes()).isTrue();
	}

	@Test
	void testHasAttributes_false() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(emptyToken);
		assertThat(cut.hasAttributes()).isFalse();
	}

	@Test
	void testHasAttributes_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.hasAttributes()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("hasAttributes")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	void testGetSystemAttribute() throws XSUserInfoException {
		String[] systemAttributes = cut.getSystemAttribute("xs.saml.groups");
		assertThat(systemAttributes).contains("g1");
	}

	@Test
	void testCheckScope() throws XSUserInfoException {
		assertThat(cut.checkScope("testScope")).isTrue();
	}

	@Test
	void testCheckLocalScope() throws XSUserInfoException {
		assertThat(cut.checkLocalScope("localScope")).isTrue();
	}

	@Test
	void testCheckLocalScope_appNameNull_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(token.withScopeConverter(null));
		assertThatThrownBy(() -> cut.checkLocalScope("localScope")).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	void testGetAdditionalAuthAttribute() throws XSUserInfoException {
		assertThat(cut.getAdditionalAuthAttribute("external_id")).isEqualTo("abcd1234");
	}

	@Test
	void testGetCloneServiceInstanceId() throws XSUserInfoException {
		assertThat(cut.getCloneServiceInstanceId()).isEqualTo("brokerCloneServiceInstanceId");
	}

	@Test
	void testGetGrantType() throws XSUserInfoException {
		assertThat(cut.getGrantType()).isEqualTo("urn:ietf:params:oauth:grant-type:saml2-bearer");
	}

	@Test
	void isForeignModeIsTrue_whenConfigurationIsNotAvailable() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(token);
		assertThat(cut.isInForeignMode()).isTrue();
	}

	@Test
	void testGetSubaccountId() throws XSUserInfoException {
		assertThat(cut.getSubaccountId()).isEqualTo("paas");
	}

	@Test
	void testGetSubaccountIdFromExternalAttributes() throws XSUserInfoException {
		String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzMxOTUvdG9rZW5fa2V5cyIsImtpZCI6ImxlZ2FjeS10b2tlbi1rZXkifQ.ewogICJqdGkiOiAiOGU3YjNiMDAtNzc1MS00YjQ2LTliMWEtNWE0NmEyYTFkNWI4IiwKICAieHMudXNlci5hdHRyaWJ1dGVzIjogewogICAgImNvc3QtY2VudGVyIjogWwogICAgICAiMDgxNSIsCiAgICAgICI0NzExIgogICAgXSwKICAgICJjb3VudHJ5IjogWwogICAgICAiR2VybWFueSIKICAgIF0KICB9LAogICAgInhzLnN5c3RlbS5hdHRyaWJ1dGVzIjogewogICAgInhzLnNhbWwuZ3JvdXBzIjogWwogICAgICAiZzEiCiAgICBdLAogICAgInhzLnJvbGVjb2xsZWN0aW9ucyI6IFsicmMxIl0KICB9LAogICJzdWIiOiAiMTAwMjE5MSIsCiAgInNjb3BlIjogWwogICAgImphdmEtaGVsbG8td29ybGQuRGlzcGxheSIsCiAgICAib3BlbmlkIiwKICAgICJqYXZhLWhlbGxvLXdvcmxkLkRlbGV0ZSIsCiAgICAiamF2YS1oZWxsby13b3JsZC5DcmVhdGUiCiAgXSwKICAiY2xpZW50X2lkIjogInNiLWphdmEtaGVsbG8td29ybGQiLAogICJjaWQiOiAic2ItamF2YS1oZWxsby13b3JsZCIsCiAgImF6cCI6ICJzYi1qYXZhLWhlbGxvLXdvcmxkIiwKICAiZ3JhbnRfdHlwZSI6ICJhdXRob3JpemF0aW9uX2NvZGUiLAogICJ1c2VyX2lkIjogIjEwMDIxOTEiLAogICJ1c2VyX25hbWUiOiAiTXVzdGVybWFubiIsCiAgIm9yaWdpbiI6ICJ1c2VyaWRwIiwKICAiZW1haWwiOiAibWF4QGV4YW1wbGUuY29tIiwKICAiaWF0IjogMTQ0MjkxMjI0NCwKICAiZXhwIjogMTQ0Mjk1NTMyMiwKICAiaXNzIjogImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4iLAogICJ6aWQiOiAiMTEtMjItMzMiLAogICJoZGIubmFtZWR1c2VyLnNhbWwiOiAiPD94bWwgdmVyc2lvbj1cIjEuMFwiIGVuY29kaW5nPVwiVVRGLThcIj8-PHNhbWwyOkFzc2VydGlvbiB4bWxuczpzYW1sMj1cInVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb25cIiBJRD1cIl9mOTQ2YmM3Yi05MzM5LTQyMDAtYjdlYi0xYmJhNjU4MDEwNmJcIiBJc3N1ZUluc3RhbnQ9XCIyMDE1LTA5LTIyVDA4OjU1OjIyLjc1NVpcIiBWZXJzaW9uPVwiMi4wXCI-PHNhbWwyOklzc3Vlcj54czItbG9naW4tdGVzdC5jZi5zYXAtY2YuY29tLXNhbWwtbG9naW48L3NhbWwyOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPVwiaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI1wiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT1cImh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuI1wiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT1cImh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMVwiLz48ZHM6UmVmZXJlbmNlIFVSST1cIiNfZjk0NmJjN2ItOTMzOS00MjAwLWI3ZWItMWJiYTY1ODAxMDZiXCI-PGRzOlRyYW5zZm9ybXM-PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09XCJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZVwiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT1cImh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuI1wiLz48L2RzOlRyYW5zZm9ybXM-PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09XCJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMVwiLz48ZHM6RGlnZXN0VmFsdWU-bkNCRk5hUjR5ZlhIYUlDdHZaaDZUVnBYbUl3PTwvZHM6RGlnZXN0VmFsdWU-PC9kczpSZWZlcmVuY2U-PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5DVkp2SVBnZk9ZNnZtRjg5VGZtcHhZbUlWQWFRM2JtSlRhamVOTnVNRUMxWE50SndPenoyT2VGNnhWVjFvWkk1MzZLQURNeVBmTlZwRG5tdVBaQUVzNnFJRzdLVkZlWCtQMTNHUVgyMzdobURxeDFVZHRuTTk0Q2E4eVd5YnRhSXhjWStPMjBQYkFFa1RaQVpyUCtyczBtTjc4QUlGTk1KYStzSVpOYm5MdVU9PC9kczpTaWduYXR1cmVWYWx1ZT48L2RzOlNpZ25hdHVyZT48c2FtbDI6U3ViamVjdD48c2FtbDI6TmFtZUlEIEZvcm1hdD1cInVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OnVuc3BlY2lmaWVkXCI-V09MRkdBTkc8L3NhbWwyOk5hbWVJRD48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9XCJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyXCI-PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb25EYXRhIE5vdE9uT3JBZnRlcj1cIjIwMTUtMDktMjJUMTI6NTU6MjIuNzU1WlwiLz48L3NhbWwyOlN1YmplY3RDb25maXJtYXRpb24-PC9zYW1sMjpTdWJqZWN0PjxzYW1sMjpDb25kaXRpb25zIE5vdEJlZm9yZT1cIjIwMTUtMDktMjJUMDg6NTU6MjIuNzU1WlwiIE5vdE9uT3JBZnRlcj1cIjIwMTUtMDktMjJUMTI6NTU6MjIuNzU1WlwiLz48c2FtbDI6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PVwiMjAxNS0wOS0yMlQwODo1NToyMi43NTdaXCIgU2Vzc2lvbk5vdE9uT3JBZnRlcj1cIjIwMTUtMDktMjJUMDk6MDA6MjIuNzU3WlwiPjxzYW1sMjpBdXRobkNvbnRleHQ-PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDI6QXNzZXJ0aW9uPiIsCiAgImF1ZCI6IFsKICAgICJzYi1qYXZhLWhlbGxvLXdvcmxkIiwKICAgICJqYXZhLWhlbGxvLXdvcmxkIiwKICAgICJvcGVuaWQiCiAgXSwKICAiYXpfYXR0ciI6IHsKICAgICJleHRlcm5hbF9ncm91cCI6ICJkb21haW5cXGdyb3VwMSIsCiAgICAiZXh0ZXJuYWxfaWQiOiAiYWJjZDEyMzQiCiAgfSwKICAiZXh0X2F0dHIiOiB7CiAgICAic2VydmljZWluc3RhbmNlaWQiOiAiYWJjZDEyMzQiLAogICAgInpkbiI6ICJ0ZXN0c3ViZG9tYWluIiwKICAgICJzdWJhY2NvdW50aWQiOiAidGVzdC1zdWJhY2NvdW50IgogIH0KfQ.yi368lAzQi-mBajDN5oMzzREn3-3WKCrjQIBe7xXVkb8ms_42HAxMiZdrLbCf1mLoJ_CMfAWJkTW0M2GmpXBJPFcdKwsmxahSmP3Ir8nRzrK76FRn1C8biVibs0MZ7cIIq-g2H--tsrml2IkL4-hZ1v5-NCF0Aq-WCcPNsHMdWTrBxpBSRkdEqiViulbfAEXJGSqkXez5VKNX_e2eKYwgu0uJN-BpD8Pqufi3H9M9UKjISkLdsXs5LdpaFN7at6BgMbW2Ce7RVTGsk3ir--rZzQg1oUnWVOKTNEwcTCIJGxm90Smse_aDcb3CBBwnMS_KbQ723ABKhW_m2q-mWeNgg";
		cut = new XSUserInfoAdapter(new XsuaaToken(token));
		assertThat(cut.getSubaccountId()).isEqualTo("test-subaccount");
	}

	@Test
	void testGetOrigin() throws XSUserInfoException {
		assertThat(cut.getOrigin()).isEqualTo("useridp");
	}

	@Test
	void testGetOrigin_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getOrigin()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getOrigin")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	void accessAttributes_doNotExist_throwsException() throws XSUserInfoException {
		String nonExistingAttribute = "doesNotExist";
		cut = new XSUserInfoAdapter(emptyToken.withScopeConverter(new XsuaaScopeConverter(TEST_APP_ID)));

		assertThatThrownBy(() -> cut.getGrantType()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getLogonName()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getFamilyName()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getZoneId()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getHdbToken()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getCloneServiceInstanceId()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getGrantType()).isInstanceOf(XSUserInfoException.class);

		assertThatThrownBy(() -> cut.getAttribute(nonExistingAttribute)).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getSystemAttribute(nonExistingAttribute)).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	void getHdbToken_AuthCodeToken_NoAttributes() throws XSUserInfoException, IOException {
		XsuaaToken token = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaXsaAccessTokenRSA256_signedWithVerificationKey.txt", UTF_8));
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId("sb-java-hello-world!i1")
				.withProperty(ServiceConstants.XSUAA.APP_ID, "java-hello-world!i1")
				.withProperty(IDENTITY_ZONE, "uaa")
				.withProperty("identityzoneid", "uaa")
				.build();

		cut = new XSUserInfoAdapter(token, configuration);

		assertThat(cut.getHdbToken()).isNotNull();
		assertThat(cut.getHdbToken()).startsWith("eyJhbGciOiAiUlMyNTYiLCJ0eXAiOiAiS");
	}

	@Test
	void getHdbToken_AudCodeToken_WithAttributes() throws XSUserInfoException {
		XsuaaToken token = mock(XsuaaToken.class);
		String mockTokenValue = "mock token value";

		when(token.getTokenValue()).thenReturn(mockTokenValue);
		when(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).thenReturn("sb-margin-assurance-ui!i1");
		when(token.hasClaim(CLIENT_ID)).thenReturn(true);
		when(token.getClientId()).thenCallRealMethod();
		when(token.getClaimAsString(TokenClaims.XSUAA.ZONE_ID)).thenReturn("uaa");
		when(token.getGrantType()).thenReturn(GrantType.AUTHORIZATION_CODE);

		JsonObject xsUserAttributes = mock(JsonObject.class);
		when(xsUserAttributes.isEmpty()).thenReturn(false);
		when(token.getClaimAsJsonObject(XS_USER_ATTRIBUTES)).thenReturn(xsUserAttributes);

		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId("sb-margin-assurance-ui!i1")
				.withProperty(ServiceConstants.XSUAA.APP_ID, "margin-assurance-ui!i1")
				.withProperty(IDENTITY_ZONE, "uaa")
				.withProperty("identityzoneid", "uaa")
				.build();

		cut = new XSUserInfoAdapter(token, configuration);

		assertThat(cut.getHdbToken()).isNotNull();
		assertThat(cut.getHdbToken()).isEqualTo(mockTokenValue);
	}

	@Test
	void isForeignModeFalse_whenTrustedClientIdSuffixMatches() throws XSUserInfoException {
		String tokenClientId = "sb-clone1!b22|brokerplanmasterapp!b123"; // azp
		String configurationAppId = "brokerplanmasterapp!b123";
		XsuaaToken token = mock(XsuaaToken.class);
		when(token.getClientId()).thenReturn(tokenClientId);
		when(token.getClaimAsString(TokenClaims.XSUAA.ZONE_ID)).thenReturn("otherIdentityZone");

		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(tokenClientId)
				.withProperty(ServiceConstants.CLIENT_ID, tokenClientId)
				.withProperty(ServiceConstants.XSUAA.APP_ID, configurationAppId)
				.withProperty(IDENTITY_ZONE, "uaa")
				.withProperty(TRUSTED_CLIENT_ID_SUFFIX, "|brokerplanmasterapp!b123")
				.build();

		cut = new XSUserInfoAdapter(token, configuration);

		assertThat(cut.isInForeignMode()).isFalse();
	}

	@Test
	void isForeignModeFalse_WhenIdentityZoneDoesNotMatchButCliendIdIsApplicationPlan()
			throws XSUserInfoException {
		String tokenClientId = "sb-application!t0123"; // azp
		String identityZone = "brokerplanmasterapp!b123"; // ext_attr -> zdn
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(tokenClientId)
				.withProperty(IDENTITY_ZONE, identityZone)
				.build();

		cut = createComponentUnderTestSpy(configuration);
		doReturn(tokenClientId).when(cut).getClientId();
		doReturn("otherIdentityZone").when(cut).getZoneId();

		assertThat(cut.isInForeignMode()).isFalse();
	}

	@Test
	void isForeignModeFalse_WhenIdentityZoneDoesNotMatchButCliendIdIsBrokerPlan()
			throws XSUserInfoException {
		String tokenClientId = "sb-application!b0123"; // azp
		String identityZone = "brokerplanmasterapp!b123"; // ext_attr -> zdn
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(tokenClientId)
				.withProperty(IDENTITY_ZONE, identityZone)
				.build();

		cut = createComponentUnderTestSpy(configuration);
		doReturn(tokenClientId).when(cut).getClientId();
		doReturn("otherIdentityZone").when(cut).getZoneId();

		assertThat(cut.isInForeignMode()).isFalse();
	}

	@Test
	void isForeignModeFalse_WhenClientIdAndIdentityZonesMatch() throws XSUserInfoException {
		String tokenClientId = "sb-application"; // azp
		String identityZone = "brokerplanmasterapp!b123"; // ext_attr -> zdn
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(tokenClientId)
				.withProperty(IDENTITY_ZONE, identityZone)
				.build();

		cut = createComponentUnderTestSpy(configuration);
		doReturn(tokenClientId).when(cut).getClientId();
		doReturn(identityZone).when(cut).getZoneId();

		assertThat(cut.isInForeignMode()).isFalse();
	}

	@Test
	void isForeignModeTrue_whenClientIdDoesNotMatchIdentityZone() throws XSUserInfoException {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withProperty(ServiceConstants.XSUAA.APP_ID, "sb-application")
				.build();

		cut = createComponentUnderTestSpy(configuration);
		doReturn("sb-application!t0123").when(cut).getClientId();
		doReturn("otherIdentityZone").when(cut).getZoneId();

		assertThat(cut.isInForeignMode()).isTrue();
	}

	@Test
	void isForeignModeTrue_whenClientIdIsMissing() throws XSUserInfoException {
		cut = createComponentUnderTestSpy();

		doReturn("brokerplanmasterapp!b123").when(cut).getZoneId();
		doThrow(new XSUserInfoException("")).when(cut).getClientId();

		assertThat(cut.isInForeignMode()).isTrue();
	}

	@Test
	void isForeignModeTrue_whenIdentityZoneIsMissing() throws XSUserInfoException {
		cut = createComponentUnderTestSpy();

		doReturn("sb-application!t0123").when(cut).getClientId();
		doThrow(new XSUserInfoException("")).when(cut).getZoneId();

		assertThat(cut.isInForeignMode()).isTrue();
	}

	@ParameterizedTest
	@MethodSource
	void canReadSystemAttributesAsListAndPlainString(Object attributeAsStringResult, Object attributeAsStringListResult, List<String> expectedAttributeResult, Class<?> expectedException) {
		Token t = setupTokenMockForSystemAttributeTest(attributeAsStringResult, attributeAsStringListResult);
		cut = new XSUserInfoAdapter(t);

		if (expectedException != null) {
			assertThatThrownBy(() -> cut.getSystemAttribute("foo")).isExactlyInstanceOf(expectedException);
		} else {
			assertThat(cut.getSystemAttribute("foo")).containsAll(expectedAttributeResult);
		}
	}

	private Token setupTokenMockForSystemAttributeTest(Object attributeAsStringResult, Object attributeAsStringListResult) {
		Token t = Mockito.mock(AccessToken.class);
		cut = new XSUserInfoAdapter(t);

		OngoingStubbing<String> whenAttributeReadAsString = when(t.getAttributeFromClaimAsString(
				eq(XS_SYSTEM_ATTRIBUTES), anyString()));
		if (attributeAsStringResult instanceof Throwable) {
			whenAttributeReadAsString.thenThrow((Throwable) attributeAsStringResult);
		} else {
			whenAttributeReadAsString.thenReturn((String) attributeAsStringResult);
		}

		OngoingStubbing<List<String>> whenAttributeReadAsStringList = when(t.getAttributeFromClaimAsStringList(
				eq(XS_SYSTEM_ATTRIBUTES), anyString()));
		if (attributeAsStringListResult instanceof Throwable) {
			whenAttributeReadAsStringList.thenThrow((Throwable) attributeAsStringListResult);
		} else {
			whenAttributeReadAsStringList.thenReturn((List<String>) attributeAsStringListResult);
		}

		return t;
	}

	private static Stream<Arguments> canReadSystemAttributesAsListAndPlainString() {
        String systemAttributeValue = "bar";
        List<String> systemAttributValuesAsList = Stream.of("bar1", "bar2").collect(Collectors.toList());

        return Stream.of(
                Arguments.of(null, null, null, XSUserInfoException.class),
                Arguments.of(new JsonParsingException(""), null, null, XSUserInfoException.class),
                Arguments.of(null, new JsonParsingException(""), null, XSUserInfoException.class),
                Arguments.of(new JsonParsingException(""), new JsonParsingException(""), null, XSUserInfoException.class),
                Arguments.of(systemAttributeValue, new JsonParsingException(""), Collections.singletonList(systemAttributeValue), null),
                Arguments.of(new JsonParsingException(""), systemAttributValuesAsList, systemAttributValuesAsList, null)
        );
    }

	private XSUserInfoAdapter createComponentUnderTestSpy() throws XSUserInfoException {
		return spy(new XSUserInfoAdapter(mock(XsuaaToken.class), mock(OAuth2ServiceConfiguration.class)));
	}

	private XSUserInfoAdapter createComponentUnderTestSpy(OAuth2ServiceConfiguration configuration)
			throws XSUserInfoException {
		return spy(
				new XSUserInfoAdapter(Mockito.mock(XsuaaToken.class), configuration));
	}

	private XsuaaToken createMockToken(GrantType grantType) {
		XsuaaToken mockToken = mock(XsuaaToken.class);
		when(mockToken.getGrantType()).thenReturn(grantType);
		return mockToken;
	}

	private XsuaaToken createMockToken() {
		return createMockToken(GrantType.SAML2_BEARER);
	}

	private XsuaaToken createMockToken(String internalToken) {
		final XsuaaToken mockToken = createMockToken();
		when(mockToken.hasClaim(EXTERNAL_CONTEXT)).thenReturn(true);
		when(mockToken.getAttributeFromClaimAsString(EXTERNAL_CONTEXT, HDB_NAMEDUSER_SAML)).thenReturn(internalToken);

		return mockToken;
	}

	private UserTokenFlow userTokenFlowMock() throws TokenFlowException {
		UserTokenFlow userTokenFlowMock = mock(UserTokenFlow.class);
		when(userTokenFlowMock.subdomain(any())).thenReturn(userTokenFlowMock);
		when(userTokenFlowMock.attributes(any())).thenReturn(userTokenFlowMock);
		when(userTokenFlowMock.token(anyString())).thenReturn(userTokenFlowMock);
		when(userTokenFlowMock.execute()).thenReturn(Mockito.mock(OAuth2TokenResponse.class));
		return userTokenFlowMock;
	}

	private ClientCredentialsTokenFlow clientCredentialsTokenFlowMock() throws TokenFlowException {
		ClientCredentialsTokenFlow clientCredentialsTokenFlowMock = mock(ClientCredentialsTokenFlow.class);
		when(clientCredentialsTokenFlowMock.subdomain(any())).thenReturn(clientCredentialsTokenFlowMock);
		when(clientCredentialsTokenFlowMock.attributes(any())).thenReturn(clientCredentialsTokenFlowMock);
		when(clientCredentialsTokenFlowMock.execute()).thenReturn(Mockito.mock(OAuth2TokenResponse.class));
		return clientCredentialsTokenFlowMock;
	}
}