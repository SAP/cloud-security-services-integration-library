package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static com.sap.cloud.security.config.cf.CFConstants.Plan.BROKER;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class CFOAuth2ServiceConfigurationTest {

	private CFOAuth2ServiceConfiguration cut;

	public CFOAuth2ServiceConfigurationTest() throws IOException {
		String vcapXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);

		JsonObject serviceJsonObject = new DefaultJsonObject(vcapXsuaa).getJsonObjects(Service.XSUAA.getCFName())
				.get(0);
		cut = CFEnvParser.extract(Service.XSUAA, serviceJsonObject);
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
		assertThat(cut.getProperty(XSUAA.UAA_DOMAIN)).isEqualTo("auth.com");
	}

	@Test
	public void getProperty() {
		assertThat(cut.getProperty("xsappname")).isEqualTo("java-hello-world");
	}

	@Test
	public void getPlan() {
		assertThat(cut.getPlan()).isEqualTo(BROKER);
	}

	@Test
	public void getService() {
		assertThat(cut.getService()).isEqualTo(Service.XSUAA);
	}

}