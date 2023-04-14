/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.json.JsonParsingException;
import org.junit.Before;
import org.junit.Test;

import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.VERIFICATION_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class VcapServicesParserTest {

	private VcapServicesParser cut;

	@Before
	public void setUp() {
		cut = VcapServicesParser.fromFile("/vcapServices/vcapSimple.json");
	}

	@Test
	public void fromFile_loadsConfiguration() {
		OAuth2ServiceConfiguration oAuth2ServiceConfiguration = cut.createConfiguration();

		assertThat(oAuth2ServiceConfiguration.getClientId()).isEqualTo("clientId");
		assertThat(oAuth2ServiceConfiguration.getProperty(CFConstants.SERVICE_PLAN)).isEqualTo("broker");
	}

	@Test
	public void fromFile_loadsConfiguration_PropertiesAreOverridden() {
		OAuth2ServiceConfiguration oAuth2ServiceConfiguration = cut.createConfiguration();

		assertThat(oAuth2ServiceConfiguration.getProperty(VERIFICATION_KEY)).isNull();
		assertThat(oAuth2ServiceConfiguration.getClientSecret()).isNull();
	}

	@Test
	public void fromFile_resourceDoesNotExits_throwsException() {
		assertThatThrownBy(() -> VcapServicesParser.fromFile("/doesNotExist.json"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Resource not found: /doesNotExist.json");
	}

	@Test
	public void fromFile_rejectsConfigurationWithClientCredentials() {
		assertThatThrownBy(() -> VcapServicesParser.fromFile("/vcapServices/vcapWithClientSecret.json"))
				.isInstanceOf(JsonParsingException.class)
				.hasMessageContaining("Client secret must not be provided!");
	}

	@Test
	public void fromFile_rejectsVcapWithoutBinding() {
		assertThatThrownBy(() -> VcapServicesParser.fromFile("/vcapServices/vcapWithoutBinding.json"))
				.isInstanceOf(JsonParsingException.class)
				.hasMessageContaining("No supported binding found in VCAP_SERVICES!");
	}

}