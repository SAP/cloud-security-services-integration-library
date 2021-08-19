package com.sap.cloud.security.config.k8s;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.Assert.assertEquals;

public class K8sEnvironmentTest {

    private static Environment cut;
    private static final WireMockServer wireMockServer = new WireMockServer(wireMockConfig().port(1111));

    @Before
    public void init() throws IOException {
        String token = IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8);
        String serviceInstances = IOUtils.resourceToString("/k8s/serviceInstances.json", StandardCharsets.UTF_8);
        String servicePlans = IOUtils.resourceToString("/k8s/servicePlans.json", StandardCharsets.UTF_8);

        wireMockServer.stubFor(post("/oauth/token").willReturn(ok().withHeader("Content-Type", "application/json").withBody("{\"access_token\": \""+ token + "\",  \"expires_in\": 1799}")));
        wireMockServer.stubFor(get("/v1/service_plans").willReturn(ok().withHeader("Content-Type", "application/json").withBody(servicePlans)));
        wireMockServer.stubFor(get("/v1/service_instances").willReturn(ok().withHeader("Content-Type", "application/json").withBody(serviceInstances)));
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
        assertEquals("xsuaaClientId", config.getClientId());
    }

    @Test
    public void getIasConfiguration() {
        OAuth2ServiceConfiguration config = cut.getIasConfiguration();
        assertEquals("iasClientId2", config.getClientId());
    }

    @Test
    public void getNumberOfXsuaaConfigurations() {
        assertEquals(2, cut.getNumberOfXsuaaConfigurations());
    }

    @Test
    public void getXsuaaConfigurationForTokenExchange() {
        OAuth2ServiceConfiguration config = cut.getXsuaaConfigurationForTokenExchange();
        assertEquals("xsuaaBrokerClientId",config.getClientId());
    }

}