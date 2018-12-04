/**
 * 
 */
package com.sap.cloud.security.xsuaa;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.sap.cloud.security.xsuaa.util.InjectVcapServiceRule;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { SsoExampleBean.class })
public class EnableSsoPropertySourceFactoryTest {

	@ClassRule
	public static InjectVcapServiceRule server = new InjectVcapServiceRule();

	@Autowired
	SsoExampleBean exampleBean;

	/**
	 * @throws java.lang.Exception
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {

	}

	/**
	 * @throws java.lang.Exception
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	/**
	 * Test method for {@link com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory#createPropertySource(java.lang.String, org.springframework.core.io.support.EncodedResource)}.
	 */
	@Test
	public void testSsoProperty() {
		assertThat(exampleBean.getUserAuthorizationUri())
				.isEqualTo("http://localhost:8080/uaa/oauth/authorize");
	}

}

@Configuration
@EnableXsuaaOauth2Config
class SsoExampleBean {

	@Value("${xsuaa.url:}")
	private String xsuaaUrl;

	@Value("${xsuaa.unknown:}")
	private String unknown;

	@Value("${security.oauth2.client.userAuthorizationUri}")
	private String userAuthorizationUri;

	/**
	 * @return the xsuaaUrl
	 */
	public String getXsuaaUrl() {
		return xsuaaUrl;
	}

	/**
	 * @param xsuaaUrl
	 *            the xsuaaUrl to set
	 */
	public void setXsuaaUrl(String xsuaaUrl) {
		this.xsuaaUrl = xsuaaUrl;
	}

	/**
	 * @return the unknown
	 */
	public String getUnknown() {
		return unknown;
	}

	/**
	 * @param unknown
	 *            the unknown to set
	 */
	public void setUnknown(String unknown) {
		this.unknown = unknown;
	}

	/**
	 * @return the userAuthorizationUri
	 */
	public String getUserAuthorizationUri() {
		return userAuthorizationUri;
	}

	/**
	 * @param userAuthorizationUri
	 *            the userAuthorizationUri to set
	 */
	public void setUserAuthorizationUri(String userAuthorizationUri) {
		this.userAuthorizationUri = userAuthorizationUri;
	}

}
