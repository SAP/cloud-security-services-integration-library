package adapter.xs;

import com.sap.cloud.security.token.XsuaaScopeConverter;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.xsa.security.container.XSUserInfoException;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
@Ignore
public class XSUserInfoAdapterTest {

	public static final String TEST_APP_ID = "testApp";
	private XSUserInfoAdapter userInfo;

	@Before
	public void setUp() throws Exception {
		//		accessToken = JWTUtil.createMultiTenancyJWT("123");
		//
		//		JwtToken jwtToken = JwtTokenHelper.decode(accessToken);
		//		Map<String, Object> claims = UaaTokenUtils.getClaims(jwtToken);

		XsuaaToken token = new XsuaaToken(
				"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkMjFmNWRlOS1kNzYxLTQ3YTItYjZkNC0yZDgzMTYxNTg0ZDkiLCJhel9hdHRyIjp7ImV4dGVybmFsX2lkIjoiYWJjZDEyMzQifSwieHMudXNlci5hdHRyaWJ1dGVzIjp7InVzckF0dHIiOlsidGVzdCJdfSwidXNlcl9uYW1lIjoiVGVzdFVzZXIiLCJvcmlnaW4iOiJ1c2VyaWRwIiwiaXNzIjoiaHR0cDovL3BhYXMubG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIiwieHMuc3lzdGVtLmF0dHJpYnV0ZXMiOnsieHMuc2FtbC5ncm91cHMiOlsiZzEiXSwieHMucm9sZWNvbGxlY3Rpb25zIjpbXX0sImdpdmVuX25hbWUiOiJUZXN0VXNlciIsImNsaWVudF9pZCI6Im15Q2xpZW50SWQiLCJhdWQiOiJbXSIsImV4dF9hdHRyIjp7ImVuaGFuY2VyIjoiWFNVQUEiLCJ6ZG4iOiJwYWFzIiwiYWNsIjpbImFwcDEhdDIzIl0sInNlcnZpY2VpbnN0YW5jZWlkIjoiYnJva2VyQ2xvbmVTZXJ2aWNlSW5zdGFuY2VJZCJ9LCJ6aWQiOiJwYWFzIiwiZ3JhbnRfdHlwZSI6InVybjppZXRmOnBhcmFtczpvYXV0aDpncmFudC10eXBlOnNhbWwyLWJlYXJlciIsInVzZXJfaWQiOiJkMjFmNWRlOS1kNzYxLTQ3YTItYjZkNC0yZDgzMTYxNTg0ZDkiLCJhenAiOiJzYi1jbG9uZTEhYjV8TFItbWFzdGVyIWI1Iiwic2NvcGUiOlsib3BlbmlkIiwidGVzdFNjb3BlIiwidGVzdEFwcC5sb2NhbFNjb3BlIl0sImV4cCI6IjE1Nzk2OTYzODIiLCJmYW1pbHlfbmFtZSI6InVua25vd24ub3JnIiwiaWF0IjoiMTUzMjQxNjg0OSIsImp0aSI6ImNmMzQ4MWRiNjQ5YTRhYTA4YjVlZjNjMjJmN2FiOTRmIiwiZW1haWwiOiJUZXN0VXNlckB1YWEub3JnIiwicmV2X3NpZyI6ImI4NTA3NTZhIiwiY2lkIjoic2ItY2xvbmUxIWI1fExSLW1hc3RlciFiNSJ9.d1lS2889TKWejuzBHSNnfKAUJjJxbQF0nDovez5sq9BrLKSobH3C4dT-aiko6r78pfOa2HA1e9VRCyeI0Kj2cCOnFHbVSeIUpjJja0j8nZscA9TAYmWDOZcmMmUIa-StdJD8uZWN78QvTjHc8y0vQ2ohV45xJs9uPmpLFABKGYPJjasWUMK2CZ9lEcKcw8ANcuGte4Ss8tklQDF69pXjGOfgGb1sKUDCiQdoaMHi23dMx6-6yW4SEPpyErhQNk4j3qGHzn7pwfuybZbLwL68iZlvph-B1iLmw9vmA1Ix6njnJy5NrLKX14bnKJobMdgRQ2jEDRs-DKb6_sfjZwFhKQ==");
		userInfo = new XSUserInfoAdapter(
				token.withScopeConverter(new XsuaaScopeConverter(TEST_APP_ID)));
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testGetLogonName() throws XSUserInfoException {
		assertThat(userInfo.getLogonName()).isEqualTo("TestUser");
	}

	@Test
	public void testGetGivenName() throws XSUserInfoException {
		assertThat(userInfo.getGivenName()).isEqualTo("TestUser");
	}

	@Test
	public void testGetFamilyName() throws XSUserInfoException {
		assertThat(userInfo.getFamilyName()).isEqualTo("unknown.org");
	}

	@Test
	public void testGetIdentityZone() throws XSUserInfoException {
		assertThat(userInfo.getIdentityZone()).isEqualTo("paas");
	}

	@Test
	public void testGetSubdomain() throws XSUserInfoException {
		assertThat(userInfo.getSubdomain()).isEqualTo("paas");
	}

	@Test
	public void testGetClientId() throws XSUserInfoException {
		assertThat(userInfo.getClientId()).isEqualTo("sb-clone1!b5|LR-master!b5");
	}

	// TODO 21.01.20 c5295400: does not exist in XSUserInfo??
	//	@Test
	//	public void testGetExpirationDate() throws XSUserInfoException {
	//		Date d = new Date(System.currentTimeMillis());
	//		assertThat(userInfo.getExpirationDate().getTime()).isCloseTo(System.currentTimeMillis(), Offset.offset(5000L));
	//	}

	@Test
	public void testGetJsonValue() throws XSUserInfoException {
		assertThat(userInfo.getJsonValue("cid")).isEqualTo("sb-clone1!b5|LR-master!b5");
	}

	@Test
	public void testGetEmail() throws XSUserInfoException {
		assertThat(userInfo.getEmail()).isEqualTo("TestUser@uaa.org");
	}

	@Test
	public void testGetDBToken() throws XSUserInfoException {
		assertThat(userInfo.getDBToken()).isEqualTo(userInfo.getAppToken());
	}

	@Test
	public void testGetHdbToken() throws XSUserInfoException {
		assertThat(userInfo.getHdbToken()).isEqualTo(userInfo.getAppToken());
	}

	@Test
	@Ignore
	// TODO 22.01.20 c5295400: load from file
	public void testGetAppToken() throws XSUserInfoException {
		assertThat(userInfo.getAppToken()).startsWith(
				"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkMjFmNWRlOS1kNzYxLTQ3YTItYjZkNC0yZDgzMTYxNTg0ZDkiLCJhel9hdHRyIjp7ImV4dGVybmFsX2lkIjoiYWJjZDEyMzQifSwieHMudXNlci5hdHRyaWJ1dGVzIjp7fSwidXNlcl9uYW1lIjoiVGVzdFVzZXIiLCJvcmlnaW4i");
	}
	//
	//	@Test
	//	public void testGetToken() throws XSUserInfoException, TokenValidationException {
	//		JwtToken jwtToken = JwtTokenHelper.decode(accessToken);
	//		Map<String, Object> claims = UaaTokenUtils.getClaims(jwtToken);
	//		userInfo = new UserInfo(claims, "testApp", accessToken);
	//		assertThat(userInfo.getToken("SYSTEM", "HDB")).startsWith(
	//				"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImxlZ2FjeS1LaWQifQ.ewogICJqdGkiOiAiMzc1ODdlOGM0NWI4NGE4NTgyMDc0NGMxNDU5OTEwYjUiLAogICJleHRfYXR0ciI6IHsKICA");
	//	}

	@Test
	public void testGetAttribute() throws XSUserInfoException {
		String[] attribute = userInfo.getAttribute("usrAttr");
		assertThat(attribute).contains("test");
	}

	@Test
	public void testHasAttributes() throws XSUserInfoException {
		assertThat(userInfo.hasAttributes()).isTrue();
	}

	@Test
	public void testGetSystemAttribute() throws XSUserInfoException {
		String[] systemAttributes = userInfo.getSystemAttribute("xs.saml.groups");
		assertThat(systemAttributes).contains("g1");
	}

	@Test
	public void testCheckScope() throws XSUserInfoException {
		assertThat(userInfo.checkScope("testScope")).isTrue();
	}

	@Test
	public void testCheckLocalScope() throws XSUserInfoException {
		assertThat(userInfo.checkLocalScope("localScope")).isTrue();
	}

	@Test
	public void testGetAdditionalAuthAttribute() throws XSUserInfoException {
		assertThat(userInfo.getAdditionalAuthAttribute("external_id")).isEqualTo("abcd1234");
	}

	@Test
	public void testGetCloneServiceInstanceId() throws XSUserInfoException {
		assertThat(userInfo.getCloneServiceInstanceId()).isEqualTo("brokerCloneServiceInstanceId");
	}

	@Test
	public void testGetGrantType() throws XSUserInfoException {
		assertThat(userInfo.getGrantType()).isEqualTo("urn:ietf:params:oauth:grant-type:saml2-bearer");
	}

	@Test
	public void testIsInForeignMode() throws XSUserInfoException {
		assertThat(userInfo.isInForeignMode()).isFalse();
	}

	@Test
	public void testGetSubaccountId() throws XSUserInfoException {
		assertThat(userInfo.getSubaccountId()).isEqualTo("paas");
	}

	@Test
	public void testGetOrigin() throws XSUserInfoException {
		assertThat(userInfo.getOrigin()).isEqualTo("useridp");
	}

	@Test
	public void testRequestTokenForClient() {
		// assertThat(userInfo.requestTokenForClient(clientId, clientSecret, uaaUrl)).isEqualTo("useridp");
	}

	@Test
	public void testRequestToken() {
		// fail("Not yet implemented");
	}

}