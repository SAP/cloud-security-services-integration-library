package sample.spring.xsuaa.config;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import sample.spring.xsuaa.TokenBrokerResolver;

import static org.mockito.Mockito.mock;

public class TokenBrokerTestConfiguration {

	/**
	 * Creates a mock XsuaaOAuth2TokenService for testing.
	 */
	@Bean
	@Primary
	public XsuaaOAuth2TokenService mockTokenService() {
		return mock(XsuaaOAuth2TokenService.class);
	}

	/**
	 * Makes {@link TokenBrokerResolver} use the mocked XsuaaOAuth2TokenService for testing.
	 */
	@Bean
	public XsuaaTokenFlows tokenFlows(XsuaaServiceConfiguration xsuaaConfig, XsuaaOAuth2TokenService tokenService) {
		OAuth2ServiceEndpointsProvider endpointsProvider = new XsuaaDefaultEndpoints(xsuaaConfig);
		ClientIdentity clientIdentity = xsuaaConfig.getClientIdentity();
		return new XsuaaTokenFlows(tokenService, endpointsProvider, clientIdentity);
	}
}
