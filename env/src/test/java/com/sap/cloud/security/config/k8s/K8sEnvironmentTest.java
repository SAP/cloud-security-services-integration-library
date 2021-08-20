package com.sap.cloud.security.config.k8s;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class K8sEnvironmentTest {

	private static Environment cut;
	private static final WireMockServer wireMockServer = new WireMockServer(
			WireMockConfiguration.wireMockConfig().port(1111));

	@Before
	public void init() throws IOException {
		String token = IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8);
		String serviceInstances = IOUtils.resourceToString("/k8s/serviceInstances.json", StandardCharsets.UTF_8);
		String servicePlans = IOUtils.resourceToString("/k8s/servicePlans.json", StandardCharsets.UTF_8);

		wireMockServer.stubFor(
				WireMock.post("/oauth/token").willReturn(WireMock.ok().withHeader("Content-Type", "application/json")
						.withBody("{\"access_token\": \"" + token + "\",  \"expires_in\": 1799}")));
		wireMockServer.stubFor(WireMock.get("/v1/service_plans")
				.willReturn(WireMock.ok().withHeader("Content-Type", "application/json").withBody(servicePlans)));
		wireMockServer.stubFor(WireMock.get("/v1/service_instances")
				.willReturn(WireMock.ok().withHeader("Content-Type", "application/json").withBody(serviceInstances)));
		wireMockServer.start();

		String absolutePath = new File("src/test/resources").getAbsolutePath();

		K8sEnvironment.getInstance().getXsuaaConfiguration();
		cut = K8sEnvironment.getInstance()
				.withXsuaaPath(absolutePath + "/k8s/xsuaa")
				.withIasPath(absolutePath + "/k8s/ias")
				.withServiceManagerPath(absolutePath + "/k8s/service-manager");
	}

	@Test
	public void getXsuaaConfiguration() {
		OAuth2ServiceConfiguration config = cut.getXsuaaConfiguration();
		Assert.assertEquals("xsuaaClientId", config.getClientId());
	}

	@Test
	public void getIasConfiguration() {
		OAuth2ServiceConfiguration config = cut.getIasConfiguration();
		Assert.assertEquals("iasClientId2", config.getClientId());
	}

	@Test
	public void getNumberOfXsuaaConfigurations() {
		Assert.assertEquals(2, cut.getNumberOfXsuaaConfigurations());
	}

	@Test
	public void getXsuaaConfigurationForTokenExchange() {
		OAuth2ServiceConfiguration config = cut.getXsuaaConfigurationForTokenExchange();
		Assert.assertEquals("xsuaaBrokerClientId", config.getClientId());
	}

}