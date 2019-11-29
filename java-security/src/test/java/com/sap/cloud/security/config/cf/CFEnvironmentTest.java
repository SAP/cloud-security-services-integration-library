package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class CFEnvironmentTest {

	private String vcapXsuaa;
	private String vcapMultipleXsuaa;
	private String vcapIas;
	private CFEnvironment cut;

	public CFEnvironmentTest() throws IOException {
		vcapXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
		vcapMultipleXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceMultipleBindings.json", UTF_8);
		vcapIas = IOUtils.resourceToString("/vcapIasServiceSingleBinding.json", UTF_8);
	}

	@Before
	public void setUp() {
		cut = CFEnvironment.getInstance((str) -> vcapXsuaa, (str) -> null);
	}

	@Test
	public void getInstance() {
		assertThat(CFEnvironment.getInstance()).isNotSameAs(CFEnvironment.getInstance());
		assertThat(cut.getType()).isEqualTo(Environment.Type.CF);
	}

	@Test(expected = UnsupportedOperationException.class)
	public void getConfigurationOfOneIasInstance() {
		cut = CFEnvironment.getInstance((str) -> vcapIas, (str) -> null);
		// TODO IAS
		assertThat(cut.getIasServiceConfiguration()).isSameAs(cut.getIasServiceConfiguration());
		assertThat(cut.getIasServiceConfiguration().getService()).isEqualTo(Service.IAS);
		assertThat(cut.getIasServiceConfiguration().getClientId()).isEqualTo("T000297");
		assertThat(cut.getIasServiceConfiguration().getClientSecret()).startsWith("pCghfbrL");
		//assertThat(cut.getIasServiceConfiguration().getDomain()).isEqualTo("auth.com");
		assertThat(cut.getIasServiceConfiguration().getUrl().toString()).isEqualTo("https://application.acc.ondemand.com");

		assertThat(cut.getXsuaaServiceConfiguration()).isNull();
		assertThat(cut.getXsuaaServiceConfigurationForTokenExchange()).isNull();
	}

	@Test
	public void getConfigurationOfOneXsuaaInstance() {
		assertThat(cut.getXsuaaServiceConfiguration()).isSameAs(cut.getXsuaaServiceConfiguration());
		assertThat(cut.getXsuaaServiceConfiguration().getService()).isEqualTo(Service.XSUAA);
		assertThat(cut.getXsuaaServiceConfiguration().getClientId()).isEqualTo("xs2.usertoken");
		assertThat(cut.getXsuaaServiceConfiguration().getClientSecret()).isEqualTo("secret");
		assertThat(cut.getXsuaaServiceConfiguration().getDomain()).isEqualTo("auth.com");
		assertThat(cut.getXsuaaServiceConfiguration().getUrl().toString()).isEqualTo("https://paastenant.auth.com");

		assertThat(cut.getNumberOfXsuaaServices()).isEqualTo(1);
		assertThat(cut.getXsuaaServiceConfigurationForTokenExchange()).isSameAs(cut.getXsuaaServiceConfiguration());

		//assertThat(cut.getIasServiceConfiguration()).isNull(); // TODO IAS
	}

	@Test
	public void getConfigurationOfMultipleInstance() {
		cut = CFEnvironment.getInstance((str) -> vcapMultipleXsuaa, (str) -> null);

		assertThat(cut.getNumberOfXsuaaServices()).isEqualTo(2);
		CFOAuth2ServiceConfiguration appServConfig = (CFOAuth2ServiceConfiguration)cut.getXsuaaServiceConfiguration();
		CFOAuth2ServiceConfiguration brokerServConfig = (CFOAuth2ServiceConfiguration)cut.getXsuaaServiceConfigurationForTokenExchange();

		assertThat(appServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(appServConfig.getPlan()).isEqualTo(CFConstants.Plan.APPLICATION);

		assertThat(brokerServConfig).isNotEqualTo(appServConfig);
		assertThat(brokerServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(brokerServConfig.getPlan()).isEqualTo(CFConstants.Plan.BROKER);
		assertThat(brokerServConfig).isSameAs(cut.getXsuaaServiceConfigurationForTokenExchange());
	}

	@Test
	public void getConfigurationByPlan() {
		cut = CFEnvironment.getInstance((str) -> vcapMultipleXsuaa, (str) -> null);

		CFOAuth2ServiceConfiguration appServConfig = (CFOAuth2ServiceConfiguration)cut.loadByPlan(Service.XSUAA,
				CFConstants.Plan.APPLICATION);
		CFOAuth2ServiceConfiguration brokerServConfig = (CFOAuth2ServiceConfiguration)cut.loadByPlan(Service.XSUAA,
				CFConstants.Plan.BROKER);

		assertThat(appServConfig.getPlan()).isEqualTo(CFConstants.Plan.APPLICATION);
		assertThat(appServConfig).isSameAs(cut.getXsuaaServiceConfiguration());

		assertThat(brokerServConfig.getPlan()).isEqualTo(CFConstants.Plan.BROKER);
		assertThat(brokerServConfig).isSameAs(cut.getXsuaaServiceConfigurationForTokenExchange());
	}

	@Test
	public void getXsuaaServiceConfiguration_usesSystemProperties() {
		cut = CFEnvironment.getInstance((str) -> vcapXsuaa, (str) -> vcapMultipleXsuaa);

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaServiceConfiguration();

		assertThat(serviceConfiguration).isNotNull();
		assertThat(cut.getNumberOfXsuaaServices()).isEqualTo(2);
	}

	@Test
	public void getServiceConfiguration_vcapServicesNotAvailable_returnsNull() {
		cut = CFEnvironment.getInstance((str) -> null, (str) -> null);

		assertThat(cut.getXsuaaServiceConfiguration()).isNull();
		assertThat(CFEnvironment.getInstance().getXsuaaServiceConfiguration()).isNull();
//		assertThat(cut.getIasServiceConfiguration()).isNull(); // TODO IAS
	}
}