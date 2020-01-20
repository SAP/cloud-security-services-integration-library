package com.sap.cloud.security.spring.adapter;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static java.nio.charset.StandardCharsets.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SAPOfflineTokenServicesCloudTest {

	private static final OAuth2ServiceConfiguration XSUAA_CONFIGURATION = OAuth2ServiceConfigurationBuilder
			.forService(Service.XSUAA)
			.withProperty(CFConstants.XSUAA.APP_ID, "appId")
			.withProperty(CFConstants.CLIENT_ID, "clientId")
			.withProperty(CFConstants.XSUAA.UAA_DOMAIN, "localhost")
			.build();

	private static final OAuth2ServiceConfiguration IAS_CONFIGURATION = OAuth2ServiceConfigurationBuilder
			.forService(Service.IAS)
			.withProperty(CFConstants.CLIENT_ID, "clientId")
			.build();

	private SAPOfflineTokenServicesCloud cut;
	private String xsuaaToken;
	private String iasToken;

	public SAPOfflineTokenServicesCloudTest() throws IOException {
		xsuaaToken = IOUtils.resourceToString("/xsuaaScopesTokenRSA256.txt", UTF_8);
		iasToken = IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8);
	}

	@Before
	public void setUp() {
		cut = createSAPOfflineTokenServicesCloud((token) -> ValidationResults.createValid(),
				XSUAA_CONFIGURATION);
		cut.afterPropertiesSet();
	}

	@Test
	public void loadAuthentication_xsuaa() throws IOException {
		OAuth2Authentication authentication = cut.loadAuthentication(xsuaaToken);

		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getOAuth2Request()).isNotNull();
		assertThat(authentication.getOAuth2Request().getScope()).contains("openid");
	}

	@Test
	public void loadAuthentication_ias() {
		cut = createSAPOfflineTokenServicesCloud((token) -> ValidationResults.createValid(),
				IAS_CONFIGURATION);
		OAuth2Authentication authentication = cut.loadAuthentication(iasToken);

		assertThat(authentication.isAuthenticated()).isTrue();
	}


	@Test
	public void loadAuthentication_tokenIsNull_throwsException() {
		assertThatThrownBy(() -> cut.loadAuthentication(null)).isInstanceOf(InvalidTokenException.class);
	}

	@Test
	public void loadAuthentication_tokenIsMalformed_throwsException() {
		assertThatThrownBy(() -> cut.loadAuthentication("a.b.c")).isInstanceOf(InvalidTokenException.class);
	}

	@Test
	public void readAccessToken_notSupported() {
		assertThatThrownBy(() -> cut.readAccessToken("token")).isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	public void loadAuthentication_tokenValidationFailed_throwsException() {
		String errorDescription = "just not valid";
		cut = createSAPOfflineTokenServicesCloud((token) -> ValidationResults.createInvalid(errorDescription),
				XSUAA_CONFIGURATION);

		assertThatThrownBy(() -> cut.loadAuthentication(xsuaaToken)).isInstanceOf(InvalidTokenException.class)
				.hasMessageContaining(errorDescription);

	}

	@Test
	public void createInstancWithEmptyConfiguration_throwsException() {
		cut = new SAPOfflineTokenServicesCloud(Mockito.mock(OAuth2ServiceConfiguration.class));
		assertThatThrownBy(() -> cut.loadAuthentication(xsuaaToken)).isInstanceOf(IllegalStateException.class);
	}

	private SAPOfflineTokenServicesCloud createSAPOfflineTokenServicesCloud(Validator<Token> tokenValidator,
			OAuth2ServiceConfiguration serviceConfiguration) {
		return new SAPOfflineTokenServicesCloud(serviceConfiguration, tokenValidator);
	}

}