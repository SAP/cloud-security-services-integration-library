package com.sap.cloud.security.xsuaa.tokenflows;

import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.*;
import static com.sap.cloud.security.xsuaa.tokenflows.UserTokenFlow.FF_USE_JWT_BEARER_GRANT_TYPE;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;

@RunWith(MockitoJUnitRunner.class)
public class UserTokenFlowTest {

	@Mock
	private OAuth2TokenService mockTokenService;

	@Mock
	RefreshTokenFlow mockRefreshTokenFlow;

	private String userTokenToBeExchanged;
	private OAuth2TokenResponse dummyAccessToken;
	private ClientCredentials clientCredentials;
	private UserTokenFlow cut;
	private OAuth2ServiceEndpointsProvider endpointsProvider;

	private static final String JWT_ACCESS_TOKEN = "4bfad399ca10490da95c2b5eb4451d53";

	@BeforeClass
	@Deprecated
	public static void activateJwtBearerFeatureFlag() {
		String rootPath = Thread.currentThread().getContextClassLoader().getResource("").getPath();
		String appConfigPath = rootPath + "application.properties";

		Properties appProps = new Properties();
		try {
			appProps.setProperty(FF_USE_JWT_BEARER_GRANT_TYPE, "true");
			appProps.store(new FileWriter(appConfigPath), "enable feature flag FF_USE_JWT_BEARER_GRANT_TYPE");
		} catch (IOException e) {
		}
	}

	@AfterClass
	@Deprecated
	public static void removeJwtBearerFeatureFlag() {
		String rootPath = Thread.currentThread().getContextClassLoader().getResource("").getPath();
		String appConfigPath = rootPath + "application.properties";

		Properties appProps = new Properties();
		try {
			appProps.remove(FF_USE_JWT_BEARER_GRANT_TYPE);
			appProps.store(new FileWriter(appConfigPath), "remove feature flag FF_USE_JWT_BEARER_GRANT_TYPE");
		} catch (IOException e) {
		}
	}

	@Before
	public void setup() throws TokenFlowException {
		this.userTokenToBeExchanged = buildMockJwt();
		this.dummyAccessToken = new OAuth2TokenResponse(JWT_ACCESS_TOKEN, 441231, REFRESH_TOKEN);
		this.clientCredentials = new ClientCredentials("clientId", "clientSecret");
		this.endpointsProvider = new XsuaaDefaultEndpoints(XSUAA_BASE_URI);
		this.cut = new UserTokenFlow(mockTokenService, mockRefreshTokenFlow, endpointsProvider, clientCredentials);
	}

	private String buildMockJwt() {
		return new JwtGenerator().addScopes("uaa.user").getToken().getTokenValue();
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new UserTokenFlow(null, mockRefreshTokenFlow, endpointsProvider, clientCredentials);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2TokenService");

		assertThatThrownBy(() -> {
			new UserTokenFlow(mockTokenService, null,
					endpointsProvider, clientCredentials);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("RefreshTokenFlow");

		assertThatThrownBy(() -> {
			new UserTokenFlow(mockTokenService, mockRefreshTokenFlow, null, clientCredentials);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2ServiceEndpointsProvider");

		assertThatThrownBy(() -> {
			new UserTokenFlow(mockTokenService, mockRefreshTokenFlow, endpointsProvider, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("ClientCredentials");
	}

	@Test
	public void execute_throwsIfMandatoryFieldsNotSet() {
		assertThatThrownBy(() -> {
			cut.execute();
		}).isInstanceOf(IllegalStateException.class);

		assertThatThrownBy(() -> {
			cut.execute();
		}).isInstanceOf(IllegalStateException.class).hasMessageContaining("User token not set");
	}

	@Test
	public void execute_throwsIfServiceRaisesException() throws OAuth2ServiceException {
		when(mockTokenService
				.retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI),
						eq(clientCredentials),
						eq(userTokenToBeExchanged),
						isNull(), isNull()))
								.thenThrow(new OAuth2ServiceException("exception executed REST call"));

		assertThatThrownBy(() -> {
			cut.token(userTokenToBeExchanged)
					.execute();
		}).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(
						"Error requesting token with grant_type 'user_token'");
	}

	@Test
	public void execute() throws TokenFlowException, OAuth2ServiceException {
		when(mockTokenService
				.retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI),
						eq(clientCredentials),
						eq(userTokenToBeExchanged),
						isNull(), isNull()))
								.thenReturn(dummyAccessToken);

		OAuth2TokenResponse jwt = cut.token(userTokenToBeExchanged)
				.execute();

		assertThat(jwt.getAccessToken(), is(dummyAccessToken.getAccessToken()));
	}

	@Test
	public void execute_withSubdomain() throws TokenFlowException, OAuth2ServiceException {
		String subdomain = "subdomain";
		cut = new UserTokenFlow(mockTokenService, mockRefreshTokenFlow, endpointsProvider, clientCredentials);

		when(mockTokenService
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), eq(subdomain), any()))
						.thenReturn(dummyAccessToken);

		OAuth2TokenResponse jwt = cut.subdomain(subdomain).token(userTokenToBeExchanged).execute();

		assertThat(jwt.getAccessToken(), is(dummyAccessToken.getAccessToken()));
	}

	@Test
	public void execute_withAdditionalAuthorities() throws TokenFlowException, OAuth2ServiceException {
		Map<String, String> additionalAuthorities = new HashMap<String, String>();
		additionalAuthorities.put("DummyAttribute", "DummyAttributeValue");

		Map<String, String> additionalAuthoritiesParam = new HashMap<>();
		additionalAuthoritiesParam.put("authorities", "{\"az_attr\":{\"DummyAttribute\":\"DummyAttributeValue\"}}");

		when(mockTokenService
				.retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI), eq(clientCredentials),
						eq(userTokenToBeExchanged),
						isNull(), eq(additionalAuthoritiesParam)))
								.thenReturn(dummyAccessToken);

		OAuth2TokenResponse jwt = cut.token(userTokenToBeExchanged)
				.attributes(additionalAuthorities)
				.execute();

		assertThat(jwt.getAccessToken(), is(dummyAccessToken.getAccessToken()));
	}

}