package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;

import static com.sap.cloud.security.config.cf.CFConstants.Plan.APPLICATION;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class CFOAuth2ServiceConfigurationTest {

	private CFOAuth2ServiceConfiguration cut;

	public CFOAuth2ServiceConfigurationTest() throws IOException {
		String singleBindingJsonString = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
		JsonObject binding = new DefaultJsonObject(singleBindingJsonString).getJsonObjects("xsuaa").get(0);

		cut = new CFOAuth2ServiceConfiguration(binding);
	}

	@Test
	public void getClientId() {
		assertThat(cut.getClientId()).isEqualTo("xs2.usertoken");
	}

	@Test
	public void getClientSecret() {
		assertThat(cut.getClientSecret()).isEqualTo("secret");
	}

	@Test
	public void getUrl() {
		assertThat(cut.getUrl()).isEqualTo(URI.create("https://paastenant.auth.com"));
	}

	@Test
	public void getDomain() {
		assertThat(cut.getDomain()).isEqualTo("auth.com");
	}

	@Test
	public void getProperty() {
		assertThat(cut.getProperty("xsappname")).isEqualTo("java-hello-world");
	}

	@Test
	public void getPlan() {
		assertThat(cut.getPlan()).isEqualTo(APPLICATION);
	}
}