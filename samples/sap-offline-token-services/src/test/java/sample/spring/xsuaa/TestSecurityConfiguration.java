package sample.spring.xsuaa;

import com.sap.cloud.security.adapter.spring.SAPOfflineTokenServicesCloud;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.SecurityTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.APP_ID;
import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.UAA_DOMAIN;

@Configuration
class TestSecurityConfiguration {

	@Bean
	protected SAPOfflineTokenServicesCloud offlineTokenServicesBean() {
		return new SAPOfflineTokenServicesCloud(
				OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
						.withUrl("http://localhost")
						.withProperty(UAA_DOMAIN, SecurityTest.DEFAULT_DOMAIN)
						.withProperty(APP_ID, SecurityTest.DEFAULT_APP_ID)
						.withClientId(SecurityTest.DEFAULT_CLIENT_ID)
						.build())
				.setLocalScopeAsAuthorities(true);
	}

}
