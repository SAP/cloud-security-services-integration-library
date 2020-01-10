package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.Map;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static com.sap.cloud.security.config.cf.CFConstants.SERVICE_PLAN;
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

	@Test
	public void getCFServiceConfigurationAndCredentialsAsMap() {
		String vcapServices = vcapXsuaa;
		JsonObject serviceJsonObject = new DefaultJsonObject(vcapServices).getJsonObjects(Service.XSUAA.getCFName())
				.get(0);
		Map<String, String> xsuaaConfigMap = serviceJsonObject.getKeyValueMap();
		Map<String, String> credentialsMap = serviceJsonObject.getJsonObject(CREDENTIALS).getKeyValueMap();

		assertThat(xsuaaConfigMap.size()).isEqualTo(4);
		assertThat(credentialsMap.size()).isEqualTo(10);
		assertThat(credentialsMap.get(CLIENT_SECRET)).isEqualTo("secret");
	}

	// TODO IAS
	@Test(expected = UnsupportedOperationException.class)
	public void getConfigurationOfOneIasInstance() {
		cut = CFEnvironment.getInstance((str) -> vcapIas, (str) -> null);
		assertThat(cut.getIasConfiguration()).isSameAs(cut.getIasConfiguration());
		assertThat(cut.getIasConfiguration().getService()).isEqualTo(Service.IAS);
		assertThat(cut.getIasConfiguration().getClientId()).isEqualTo("T000297");
		assertThat(cut.getIasConfiguration().getClientSecret()).startsWith("pCghfbrL");
		// assertThat(cut.getIasServiceConfiguration().getDomain()).isEqualTo("auth.com");
		assertThat(cut.getIasConfiguration().getUrl().toString())
				.isEqualTo("https://application.acc.ondemand.com");

		assertThat(cut.getXsuaaConfiguration()).isNull();
		assertThat(cut.getXsuaaConfigurationForTokenExchange()).isNull();
	}

	@Test
	public void getConfigurationOfOneXsuaaInstance() {
		assertThat(cut.getXsuaaConfiguration()).isSameAs(cut.getXsuaaConfiguration());
		assertThat(cut.getXsuaaConfiguration().getService()).isEqualTo(Service.XSUAA);
		assertThat(cut.getXsuaaConfiguration().getClientId()).isEqualTo("xs2.usertoken");
		assertThat(cut.getXsuaaConfiguration().getClientSecret()).isEqualTo("secret");
		assertThat(cut.getXsuaaConfiguration().getProperty(XSUAA.UAA_DOMAIN)).isEqualTo("auth.com");
		assertThat(cut.getXsuaaConfiguration().getUrl().toString()).isEqualTo("https://paastenant.auth.com");

		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(1);
		assertThat(cut.getXsuaaConfigurationForTokenExchange()).isSameAs(cut.getXsuaaConfiguration());

		// assertThat(cut.getIasConfiguration()).isNull(); // TODO IAS
	}

	@Test
	public void getConfigurationOfMultipleInstance() {
		cut = CFEnvironment.getInstance((str) -> vcapMultipleXsuaa, (str) -> null);

		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(2);
		OAuth2ServiceConfiguration appServConfig = cut.getXsuaaConfiguration();
		OAuth2ServiceConfiguration brokerServConfig = cut.getXsuaaConfigurationForTokenExchange();

		assertThat(appServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(Plan.from(appServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.APPLICATION);

		assertThat(brokerServConfig).isNotEqualTo(appServConfig);
		assertThat(brokerServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(Plan.from(brokerServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.BROKER);
		assertThat(brokerServConfig).isSameAs(cut.getXsuaaConfigurationForTokenExchange());
	}

	@Test
	public void getConfigurationByPlan() {
		cut = CFEnvironment.getInstance((str) -> vcapMultipleXsuaa, (str) -> null);

		OAuth2ServiceConfiguration appServConfig = cut.loadByPlan(Service.XSUAA,
				Plan.APPLICATION);
		OAuth2ServiceConfiguration brokerServConfig = cut.loadByPlan(Service.XSUAA,
				Plan.BROKER);

		assertThat(Plan.from(appServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.APPLICATION);
		assertThat(appServConfig).isSameAs(cut.getXsuaaConfiguration());

		assertThat(Plan.from(brokerServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.BROKER);
		assertThat(brokerServConfig).isSameAs(cut.getXsuaaConfigurationForTokenExchange());
	}

	@Test
	public void getXsuaaServiceConfiguration_usesSystemProperties() {
		cut = CFEnvironment.getInstance((str) -> vcapXsuaa, (str) -> vcapMultipleXsuaa);

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaConfiguration();

		assertThat(serviceConfiguration).isNotNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(2);
	}

	@Test
	public void getServiceConfiguration_vcapServicesNotAvailable_returnsNull() {
		cut = CFEnvironment.getInstance((str) -> null, (str) -> null);

		assertThat(cut.getXsuaaConfiguration()).isNull();
		// assertThat(cut.getIasConfiguration()).isNull(); // TODO IAS
	}
}