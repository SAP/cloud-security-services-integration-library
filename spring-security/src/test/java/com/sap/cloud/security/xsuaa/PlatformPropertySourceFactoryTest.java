package com.sap.cloud.security.xsuaa;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.sap.cloud.security.xsuaa.util.EnvironmentInjectionUtil;
import com.sap.cloud.security.xsuaa.util.InjectVcapServiceRule;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { PlatformPropertyTestBean.class })
public class PlatformPropertySourceFactoryTest {

	private static final String VCAP_SERVICES = "VCAP_SERVICES";

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		String injectionValue = IOUtils.toString(InjectVcapServiceRule.class.getResourceAsStream("/vcap_cfuaa.json"), StandardCharsets.UTF_8);
		EnvironmentInjectionUtil.injectEnvironmentVariable(VCAP_SERVICES, injectionValue);
		if (StringUtils.isNotBlank(injectionValue)) {
			assertThat(System.getenv(VCAP_SERVICES)).isNotEmpty();
		}
	}

	@Autowired
	PlatformPropertyTestBean exampleBean;

	@Test
	public void testInjectedPropertyValue() {
		assertThat(System.getenv("VCAP_SERVICES")).isNotEmpty();
		assertThat(exampleBean.getXsuaaUrl()).isEqualTo("https://lu356076.dhcp.wdf.sap.corp:30132/uaa-security");
	}

	@Test
	public void testUnknownPropertyValue() {
		assertThat(exampleBean.getUnknown()).isEqualTo("");
	}

}

@Configuration
@PropertySource(factory = PlatformPropertySourceFactory.class, value = { "" })
class PlatformPropertyTestBean {

	@Value("${vcap.services.user-provided.credentials.authentication.uaaurl:}")
	private String xsuaaUrl;

	@Value("${xsuaa.unknown:}")
	private String unknown;

	public PlatformPropertyTestBean() {
	}

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

}
