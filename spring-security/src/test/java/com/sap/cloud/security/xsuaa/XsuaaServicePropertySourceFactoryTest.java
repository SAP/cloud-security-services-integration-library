package com.sap.cloud.security.xsuaa;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.sap.cloud.security.xsuaa.util.InjectVcapServiceRule;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { XSUAAVcapPropertyTestBean.class })
public class XsuaaServicePropertySourceFactoryTest {

	@ClassRule
	public static InjectVcapServiceRule server = new InjectVcapServiceRule();

	@Autowired
	XSUAAVcapPropertyTestBean exampleBean;

	@Test
	public void testInjectedPropertyValue() {
		assertThat(System.getenv("VCAP_SERVICES")).isNotEmpty();
		assertThat(exampleBean.getXsuaaUrl()).isEqualTo("http://localhost:8080/uaa");
	}

	@Test
	public void testUnknownPropertyValue() {
		assertThat(exampleBean.getUnknown()).isEqualTo("");
	}

}

@Configuration
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "" })
class XSUAAVcapPropertyTestBean {

	@Value("${xsuaa.url:}")
	private String xsuaaUrl;

	@Value("${xsuaa.unknown:}")
	private String unknown;

	public XSUAAVcapPropertyTestBean() {
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
