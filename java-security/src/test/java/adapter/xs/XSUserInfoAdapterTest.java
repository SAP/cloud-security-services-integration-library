package adapter.xs;

import com.sap.cloud.security.token.XsuaaScopeConverter;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.xsa.security.container.XSUserInfoException;
import org.apache.commons.io.IOUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static java.nio.charset.StandardCharsets.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Ignore
public class XSUserInfoAdapterTest {

	public static final String TEST_APP_ID = "testApp";
	private XSUserInfoAdapter cut;

	@Before
	public void setUp() throws IOException, XSUserInfoException {
		XsuaaToken token = new XsuaaToken(IOUtils.resourceToString("/xsuaaUserInfoAdapterToken.txt", UTF_8));
		cut = new XSUserInfoAdapter(token.withScopeConverter(new XsuaaScopeConverter(TEST_APP_ID)));
	}


	@Test
	public void testGetLogonName() throws XSUserInfoException {
		assertThat(cut.getLogonName()).isEqualTo("TestUser");
	}

	@Test
	public void testGetGivenName() throws XSUserInfoException {
		assertThat(cut.getGivenName()).isEqualTo("TestUser");
	}

	@Test
	public void testGetFamilyName() throws XSUserInfoException {
		assertThat(cut.getFamilyName()).isEqualTo("unknown.org");
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

	// TODO 21.01.20 c5295400: does not exist in XSUserInfo??
	//	@Test
	//	public void testGetExpirationDate() throws XSUserInfoException {
	//		Date d = new Date(System.currentTimeMillis());
	//		assertThat(userInfo.getExpirationDate().getTime()).isCloseTo(System.currentTimeMillis(), Offset.offset(5000L));
	//	}

	@Test
	public void testGetJsonValue() throws XSUserInfoException {
		assertThat(cut.getJsonValue("cid")).isEqualTo("sb-clone1!b5|LR-master!b5");
	}

	@Test
	public void testGetEmail() throws XSUserInfoException {
		assertThat(cut.getEmail()).isEqualTo("TestUser@uaa.org");
	}

	@Test
	public void testGetDBToken() throws XSUserInfoException {
		assertThat(cut.getDBToken()).isEqualTo(cut.getAppToken());
	}

	@Test
	public void testGetHdbToken() throws XSUserInfoException {
		assertThat(cut.getHdbToken()).isEqualTo(cut.getAppToken());
	}

	@Test
	public void testGetAppToken() throws IOException {
		assertThat(cut.getAppToken()).isEqualTo(IOUtils.resourceToString("/xsuaaUserInfoAdapterToken.txt", UTF_8));
	}

	// TODO 22.01.20 c5295400: get test data to implement this
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
		String[] attribute = cut.getAttribute("usrAttr");
		assertThat(attribute).contains("test");
	}

	@Test
	public void testHasAttributes() throws XSUserInfoException {
		assertThat(cut.hasAttributes()).isTrue();
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
	public void testIsInForeignMode() throws XSUserInfoException {
		assertThat(cut.isInForeignMode()).isFalse();
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
	public void accessAttributes_doNotExist_throwsException() throws IOException, XSUserInfoException {
		String emptyTokenString = IOUtils.resourceToString("/xsuaaEmptyToken.txt", UTF_8);
		XsuaaToken emptyToken = new XsuaaToken(emptyTokenString);
		cut = new XSUserInfoAdapter(emptyToken.withScopeConverter(new XsuaaScopeConverter(TEST_APP_ID)));

		assertThat(cut.getAppToken()).isEqualTo(emptyTokenString);
		assertThatThrownBy(() -> cut.getGrantType()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getLogonName()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getFamilyName()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getIdentityZone()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getDBToken()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getCloneServiceInstanceId()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getGrantType()).isInstanceOf(XSUserInfoException.class);

		//		assertThatThrownBy(() -> cut.getJsonValue("")).isInstanceOf(XSUserInfoException.class);
		//		assertThatThrownBy(() -> cut.getAttribute("")).isInstanceOf(XSUserInfoException.class);
		//		assertThatThrownBy(() -> cut.getSystemAttribute("")).isInstanceOf(XSUserInfoException.class);
		//		assertThatThrownBy(() -> cut.checkLocalScope("localScope")).isInstanceOf(XSUserInfoException.class);
		//		assertThatThrownBy(() -> cut.isInForeignMode()).isInstanceOf(XSUserInfoException.class);
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