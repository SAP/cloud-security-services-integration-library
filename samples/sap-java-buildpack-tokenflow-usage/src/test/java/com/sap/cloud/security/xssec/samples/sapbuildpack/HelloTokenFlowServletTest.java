package com.sap.cloud.security.xssec.samples.sapbuildpack;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.*;
import com.sap.cloud.security.xsuaa.mock.MockXsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.mock.XsuaaMockWebServer;
import com.sap.cloud.security.xsuaa.mock.XsuaaRequestDispatcher;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.tokenflows.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.cache.CacheAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.net.URI;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {XsuaaMockPostProcessor.class, XsuaaMockWebServer.class, XsuaaRequestDispatcher.class,
		MockXsuaaServiceConfiguration.class })
@ActiveProfiles("uaamock")
public class HelloTokenFlowServletTest {

	@Autowired
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Test
	public void testRetrieveAccessTokenViaClientCredentialsGrant() {
		ClientCredentials clientCredentials = new ClientCredentials(xsuaaServiceConfiguration.getClientId(),
				xsuaaServiceConfiguration.getClientSecret());

		XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(
				new DefaultOAuth2TokenService(),
				new XsuaaDefaultEndpoints(xsuaaServiceConfiguration.getUaaUrl()), clientCredentials);

		tokenFlows.clientCredentialsTokenFlow();
	}
}