package com.sap.cloud.security.xsuaa;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

public class XsuaaServicesParserTest {

	@Test
	public void ignoreApiAccessPlan() throws IOException {
		String vcapMultipleBindings = IOUtils.resourceToString("/vcap_multipleBindings.json", Charset.forName("UTF-8"));
		XsuaaServicesParser cut = new XsuaaServicesParser(vcapMultipleBindings);
		Properties properties = cut.parseCredentials();
		assertThat(properties.getProperty("clientid")).isEqualTo("client-id");
	}

	@Test(expected = IllegalStateException.class)
	public void doNotAllowBrokerAndApplicationPlan() throws IOException {
		String vcapMultipleBindings = IOUtils.resourceToString("/vcap_multipleBindings.json", Charset.forName("UTF-8"));
		vcapMultipleBindings = vcapMultipleBindings.replace("apiaccess", "broker");
		XsuaaServicesParser cut = new XsuaaServicesParser(vcapMultipleBindings);
		cut.parseCredentials();
	}
}
