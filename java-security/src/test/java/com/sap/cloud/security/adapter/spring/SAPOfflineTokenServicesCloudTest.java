package com.sap.cloud.security.adapter.spring;

import com.sap.cloud.security.adapter.spring.SAPOfflineTokenServicesCloud;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class SAPOfflineTokenServicesCloudTest {

	private SAPOfflineTokenServicesCloud cut;
	private String xsuaaToken;
	private String iasToken;
	private JwtValidatorBuilder jwtValidatorBuilderMock;

	public SAPOfflineTokenServicesCloudTest() throws IOException {
		xsuaaToken = IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8);
		iasToken = IOUtils.resourceToString("/iasOidcTokenRSA256.txt", StandardCharsets.UTF_8);
	}

	@Before
	public void setUp() {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.XSUAA)
				.withProperty(CFConstants.XSUAA.APP_ID, "testApp")
				.withProperty(CFConstants.CLIENT_ID, "clientId")
				.withProperty(CFConstants.XSUAA.UAA_DOMAIN, "localhost")
				.build();

		jwtValidatorBuilderMock = Mockito.spy(JwtValidatorBuilder.getInstance(configuration));
		when(jwtValidatorBuilderMock.build()).thenReturn(
				new CombiningValidator<>(token -> ValidationResults.createValid()));

		cut = new SAPOfflineTokenServicesCloud(configuration, jwtValidatorBuilderMock);
		SecurityContext.clearToken();
	}

	@Test
	public void loadAuthentication() {
		cut.afterPropertiesSet();
		OAuth2Authentication authentication = cut.loadAuthentication(xsuaaToken);

		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getOAuth2Request()).isNotNull();
		assertThat(authentication.getOAuth2Request().getScope()).contains("ROLE_SERVICEBROKER", "uaa.resource");
		assertThat(SecurityContext.getToken().getAccessToken()).isEqualTo(xsuaaToken);
	}

	@Test
	public void loadAuthentication_ias() {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withProperty(CFConstants.CLIENT_ID, "clientId")
				.build();

		cut = new SAPOfflineTokenServicesCloud(configuration, jwtValidatorBuilderMock);

		cut.afterPropertiesSet();
		OAuth2Authentication authentication = cut.loadAuthentication(iasToken);

		assertThat(authentication.isAuthenticated()).isTrue();
	}

	@Test
	public void loadAuthenticationWithLocalScopes() throws IOException {
		xsuaaToken = IOUtils.resourceToString("/xsuaaUserInfoAdapterToken.txt", StandardCharsets.UTF_8);

		cut.afterPropertiesSet();

		OAuth2Authentication authentication = cut.loadAuthentication(xsuaaToken);
		assertThat(authentication.getOAuth2Request().getScope()).containsExactly("testApp.localScope", "openid",
				"testScope");

		cut.setLocalScopeAsAuthorities(true);
		authentication = cut.loadAuthentication(xsuaaToken);
		assertThat(authentication.getOAuth2Request().getScope()).containsExactly("localScope");
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
	public void readAccessToken() {
		assertThatThrownBy(() -> cut.readAccessToken("token")).isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	public void loadAuthentication_tokenValidationFailed_throwsException() {
		when(jwtValidatorBuilderMock.build()).thenCallRealMethod();
		cut.afterPropertiesSet();

		assertThatThrownBy(() -> cut.loadAuthentication(xsuaaToken)).isInstanceOf(InvalidTokenException.class);

		assertThat(SecurityContext.getToken()).isNull();
	}

	@Test
	public void createInstanceWithEmptyConfiguration_throwsException() {
		cut = new SAPOfflineTokenServicesCloud(Mockito.mock(OAuth2ServiceConfiguration.class));
		assertThatThrownBy(() -> cut.afterPropertiesSet()).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void createInstanceWithClientIdConfiguration_throwsException() {
		OAuth2ServiceConfiguration mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.getClientId()).thenReturn("clientId");

		cut = new SAPOfflineTokenServicesCloud(mockConfiguration);
		cut.afterPropertiesSet();
		assertThatThrownBy(() -> cut.loadAuthentication(xsuaaToken)).isInstanceOf(InvalidTokenException.class);
	}

	@Test
	public void afterPropertiesSet() {
		cut = new SAPOfflineTokenServicesCloud(Mockito.mock(OAuth2ServiceConfiguration.class), jwtValidatorBuilderMock);

		Mockito.verify(jwtValidatorBuilderMock, times(0)).build();
		cut.afterPropertiesSet();
		Mockito.verify(jwtValidatorBuilderMock, times(1)).build();
	}

}