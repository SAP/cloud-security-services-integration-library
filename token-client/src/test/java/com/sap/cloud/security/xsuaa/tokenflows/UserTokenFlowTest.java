package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.client.*;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.*;

@RunWith(MockitoJUnitRunner.class)
public class UserTokenFlowTest {

	@Mock
	private OAuth2TokenService mockTokenService;

	@Mock
	RefreshTokenFlow mockRefreshTokenFlow;

	private String mockJwt;
	private String invalidMockJwt;
	private ClientCredentials clientCredentials;
	private UserTokenFlow cut;

	private static final String JWT_ACCESS_TOKEN = "4bfad399ca10490da95c2b5eb4451d53";
	private static final String REFRESH_TOKEN = "99e2cecfa54f4957a782f07168915b69-r";

	@Before
	public void setup() throws TokenFlowException {
		this.mockJwt = buildMockJwt();
		this.invalidMockJwt = buildInvalidMockJwt();
		this.clientCredentials = new ClientCredentials("clientId", "clientSecret");
		this.cut = new UserTokenFlow(mockTokenService, mockRefreshTokenFlow,
				new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));

		// configure Refresh Token Flow Mock
		Mockito.when(mockRefreshTokenFlow.execute()).thenReturn(mockJwt);
		Mockito.when(mockRefreshTokenFlow.refreshToken(anyString())).thenReturn(mockRefreshTokenFlow);
		Mockito.when(mockRefreshTokenFlow.client(anyString())).thenReturn(mockRefreshTokenFlow);
		Mockito.when(mockRefreshTokenFlow.secret(anyString())).thenReturn(mockRefreshTokenFlow);
	}

	private String buildMockJwt() {
		return new JwtGenerator().addScopes("uaa.user").getToken().getTokenValue();
	}

	private String buildInvalidMockJwt() {
		return new JwtGenerator().getToken().getTokenValue();
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new UserTokenFlow(null, mockRefreshTokenFlow,
					new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2TokenService");

		assertThatThrownBy(() -> {
			new UserTokenFlow(mockTokenService, null,
					new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("RefreshTokenFlow");

		assertThatThrownBy(() -> {
			new UserTokenFlow(mockTokenService, mockRefreshTokenFlow, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2ServiceEndpointsProvider");
	}

	@Test
	public void execute_throwsIfMandatoryFieldsNotSet() {
		assertThatThrownBy(() -> {
			cut.execute();
		}).isInstanceOf(TokenFlowException.class);

		assertThatThrownBy(() -> {
			cut.client(clientCredentials.getId())
					.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("User token not set");

		assertThatThrownBy(() -> {
			cut.client(null)
					.secret(clientCredentials.getSecret())
					.execute();
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client ID");

		assertThatThrownBy(() -> {
			cut.client(clientCredentials.getId())
					.secret(null)
					.execute();
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client secret");
	}

	@Test
	public void test_execute_throwsIfTokenDoesNotContainUaaUserScope() {

		assertThatThrownBy(() -> {
			new UserTokenFlow(mockTokenService, mockRefreshTokenFlow,
					new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri))
							.token(invalidMockJwt)
							.client(clientCredentials.getId())
							.secret(clientCredentials.getSecret())
							.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("JWT token does not include scope 'uaa.user'");
	}

	@Test
	public void execute_throwsIfServiceRaisesException() {
		Mockito.when(mockTokenService
				.retrieveAccessTokenViaUserTokenGrant(eq(TestConstants.tokenEndpointUri), eq(clientCredentials),
						eq(mockJwt),
						isNull(), isNull()))
				.thenThrow(new OAuth2ServiceException("exception executed REST call"));

		assertThatThrownBy(() -> {
			cut.client(clientCredentials.getId())
					.secret(clientCredentials.getSecret())
					.token(mockJwt)
					.execute();
		}).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(
						"Error requesting token with grant_type 'user_token'");
	}

	@Test
	public void execute() throws TokenFlowException {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(JWT_ACCESS_TOKEN, 441231, REFRESH_TOKEN);

		Mockito.when(mockTokenService
				.retrieveAccessTokenViaUserTokenGrant(eq(TestConstants.tokenEndpointUri), eq(clientCredentials),
						eq(mockJwt),
						isNull(), isNull()))
				.thenReturn(accessToken);

		String jwt = cut.client(clientCredentials.getId())
				.secret(clientCredentials.getSecret())
				.token(mockJwt)
				.execute();

		assertThat(jwt, is(mockJwt));
	}

	@Test
	public void execute_withAdditionalAuthorities() throws TokenFlowException {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(JWT_ACCESS_TOKEN, 441231, REFRESH_TOKEN);

		Map<String, String> additionalAuthorities = new HashMap<String, String>();
		additionalAuthorities.put("DummyAttribute", "DummyAttributeValue");

		Map<String, String> additionalAuthoritiesParam = new HashMap<>();
		additionalAuthoritiesParam.put("authorities", "{\"az_attr\":{\"DummyAttribute\":\"DummyAttributeValue\"}}");

		Mockito.when(mockTokenService
				.retrieveAccessTokenViaUserTokenGrant(eq(TestConstants.tokenEndpointUri), eq(clientCredentials),
						eq(mockJwt),
						isNull(), eq(additionalAuthoritiesParam)))
				.thenReturn(accessToken);

		String jwt = cut.client(clientCredentials.getId())
				.secret(clientCredentials.getSecret())
				.token(mockJwt)
				.attributes(additionalAuthorities)
				.execute();

		assertThat(jwt, is(mockJwt));
	}

}