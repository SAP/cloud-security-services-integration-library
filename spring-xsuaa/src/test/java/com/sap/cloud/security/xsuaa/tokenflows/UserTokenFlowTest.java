package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.client.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Arrays;
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

	private Jwt mockJwt;
	private Jwt invalidMockJwt;
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

	private Jwt buildMockJwt() {
		Map<String, Object> jwtHeaders = new HashMap<String, Object>();
		jwtHeaders.put("dummyHeader", "dummyHeaderValue");

		Map<String, Object> jwtClaims = new HashMap<String, Object>();
		jwtClaims.put("scope", Arrays.asList("uaa.user", "read", "write"));

		return new Jwt("mockJwtValue", Instant.now(),
				Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
	}

	private Jwt buildInvalidMockJwt() {
		Map<String, Object> jwtHeaders = new HashMap<String, Object>();
		jwtHeaders.put("dummyHeader", "dummyHeaderValue");

		Map<String, Object> jwtClaims = new HashMap<String, Object>();
		jwtClaims.put("dummyClaim", "dummyClaimValue");

		return new Jwt("mockJwtValue", Instant.now(),
				Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
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
			cut.client(clientCredentials.getClientId())
					.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("User token not set");

		assertThatThrownBy(() -> {
			cut.client(null)
					.secret(clientCredentials.getClientSecret())
					.execute();
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("client ID");

		assertThatThrownBy(() -> {
			cut.client(clientCredentials.getClientId())
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
							.client(clientCredentials.getClientId())
							.secret(clientCredentials.getClientSecret())
							.execute();
		}).isInstanceOf(TokenFlowException.class).hasMessageContaining("JWT token does not include scope 'uaa.user'");
	}

	@Test
	public void execute_throwsIfServiceRaisesException() {
		Mockito.when(mockTokenService
				.retrieveAccessTokenViaUserTokenGrant(eq(TestConstants.tokenEndpointUri), eq(clientCredentials),
						eq(mockJwt.getTokenValue()),
						isNull()))
				.thenThrow(new OAuth2ServiceException("exception executed REST call"));

		assertThatThrownBy(() -> {
			cut.client(clientCredentials.getClientId())
					.secret(clientCredentials.getClientSecret())
					.token(mockJwt)
					.execute();
		}).isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(
						"Error requesting token with grant_type 'user_token'");
	}

	@Test
	public void execute() throws TokenFlowException {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(JWT_ACCESS_TOKEN, REFRESH_TOKEN, 441231);

		Mockito.when(mockTokenService
				.retrieveAccessTokenViaUserTokenGrant(eq(TestConstants.tokenEndpointUri), eq(clientCredentials),
						eq(mockJwt.getTokenValue()),
						isNull()))
				.thenReturn(accessToken);

		Jwt jwt = cut.client(clientCredentials.getClientId())
				.secret(clientCredentials.getClientSecret())
				.token(mockJwt)
				.execute();

		assertThat(jwt, is(mockJwt));
	}

	@Test
	public void execute_withAdditionalAuthorities() throws TokenFlowException {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(JWT_ACCESS_TOKEN, REFRESH_TOKEN, 441231);

		Map<String, String> additionalAuthorities = new HashMap<String, String>();
		additionalAuthorities.put("DummyAttribute", "DummyAttributeValue");

		Mockito.when(mockTokenService
				.retrieveAccessTokenViaUserTokenGrant(eq(TestConstants.tokenEndpointUri), eq(clientCredentials),
						eq(mockJwt.getTokenValue()),
						isNotNull()))
				.thenReturn(accessToken);

		Jwt jwt = cut.client(clientCredentials.getClientId())
				.secret(clientCredentials.getClientSecret())
				.token(mockJwt)
				.attributes(additionalAuthorities)
				.execute();

		assertThat(jwt, is(mockJwt));
	}

}