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
				"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkMjFmNWRlOS1kNzYxLTQ3YTItYjZkNC0yZDgzMTYxNTg0ZDkiLCJhel9hdHRyIjp7ImV4dGVybmFsX2lkIjoiYWJjZDEyMzQifSwieHMudXNlci5hdHRyaWJ1dGVzIjp7InVzckF0dHIiOiJbXCJ0ZXN0XCJdIn0sInVzZXJfbmFtZSI6IlRlc3RVc2VyIiwib3JpZ2luIjoidXNlcmlkcCIsImlzcyI6Imh0dHA6Ly9wYWFzLmxvY2FsaG9zdDo4MDgwL3VhYS9vYXV0aC90b2tlbiIsInhzLnN5c3RlbS5hdHRyaWJ1dGVzIjp7InhzLnNhbWwuZ3JvdXBzIjoiW1wiZzFcIl0iLCJ4cy5yb2xlY29sbGVjdGlvbnMiOiJbXSJ9LCJnaXZlbl9uYW1lIjoiVGVzdFVzZXIiLCJjbGllbnRfaWQiOiJteUNsaWVudElkIiwiYXVkIjoiW10iLCJleHRfYXR0ciI6eyJlbmhhbmNlciI6IlhTVUFBIiwiYWNsIjoiW1wiYXBwMSF0MjNcIl0iLCJ6ZG4iOiJwYWFzIiwic2VydmljZWluc3RhbmNlaWQiOiJicm9rZXJDbG9uZVNlcnZpY2VJbnN0YW5jZUlkIn0sInppZCI6InBhYXMiLCJncmFudF90eXBlIjoidXJuOmlldGY6cGFyYW1zOm9hdXRoOmdyYW50LXR5cGU6c2FtbDItYmVhcmVyIiwidXNlcl9pZCI6ImQyMWY1ZGU5LWQ3NjEtNDdhMi1iNmQ0LTJkODMxNjE1ODRkOSIsImF6cCI6InNiLWNsb25lMSFiNXxMUi1tYXN0ZXIhYjUiLCJzY29wZSI6WyJvcGVuaWQiLCJ0ZXN0U2NvcGUiLCJ0ZXN0QXBwLmxvY2FsU2NvcGUiXSwiZXhwIjoiMTU3OTY5MDMyNSIsImZhbWlseV9uYW1lIjoidW5rbm93bi5vcmciLCJpYXQiOiIxNTMyNDE2ODQ5IiwianRpIjoiY2YzNDgxZGI2NDlhNGFhMDhiNWVmM2MyMmY3YWI5NGYiLCJlbWFpbCI6IlRlc3RVc2VyQHVhYS5vcmciLCJyZXZfc2lnIjoiYjg1MDc1NmEiLCJjaWQiOiJzYi1jbG9uZTEhYjV8TFItbWFzdGVyIWI1In0=.LaT_515ZqoAMTtVaovagZHLEszDQG4dIrOPAFoP-xgtlNVkXPqO0YEZWuxkT1HMCIqghRO0bSVcovxXAf7TFHP0MFEVA2ZxH9n-Bvm1raiL0YhM52dJGI3KG0xPRPig2nk7xNla72VuqqeH1hY7BZXhi3qiy1X4k1wM3SsmcW5ma-FUD9o28zIiUEiiNT7gHzjhu_MBGaDnGME3FbMNqQN8fpNJvi_hsJG34pUv4po0zGK0NpH2m_J6O-qaNCCDNkRvbb5ou3BYxdBErzFhIAN7jLREGi5boVQEudwfAYI4IAHIqv4kY31L5Xdp1k8r-EzLQJrbg0WuKSphJ6pF9Uw==");
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
	@Ignore
	// TODO 21.01.20 c5295400: not contained in token
	public void testGetServicePlan() throws XSUserInfoException {
		// assertThat(userInfo.getServicePlan()).isEqualTo("broker");
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
	public void testGetAppToken() throws XSUserInfoException {
		// TODO 22.01.20 c5295400: load from file
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
		boolean hasAttributes = userInfo.hasAttributes();
		assertThat(hasAttributes).isTrue();
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